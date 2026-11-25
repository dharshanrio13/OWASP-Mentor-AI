"""Scan endpoints: upload, history and report retrieval (all session-scoped)."""
from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid
from collections import deque
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, Request, UploadFile
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.crud import create_scan, get_scan, list_scans
from app.database import get_db
from app.schemas import RuleSet, ScanReport, ScanStats, ScanSummary
from app.services.ai_explainer import AIExplainer, get_explainer
from app.services.scanner import analyze, get_ruleset
from app.services.zip_inspector import ZipLimits, ZipRejected, inspect_zip

logger = logging.getLogger("owasp_mentor.scans")

router = APIRouter(prefix="/api/scans", tags=["scans"])

_MAX_FILENAME_LENGTH = 100


# --------------------------------------------------------------------------
# Session ID (demo ownership only - NOT authentication)
# --------------------------------------------------------------------------
def get_session_id(x_session_id: Optional[str] = Header(default=None)) -> str:
    """Validate the X-Session-ID header and return it in canonical lowercase form.

    The session UUID only separates one browser's demo history from another's.
    Anyone who knows or guesses a UUID can read that session's reports.
    """
    if not x_session_id:
        raise HTTPException(status_code=400, detail="The X-Session-ID header is required.")
    candidate = x_session_id.strip().lower()
    try:
        parsed = uuid.UUID(candidate)
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=400, detail="X-Session-ID must be a valid UUID.") from None
    if str(parsed) != candidate:
        raise HTTPException(status_code=400, detail="X-Session-ID must be a valid UUID.")
    return str(parsed)


# --------------------------------------------------------------------------
# Rate limiting (in-memory sliding window, per process)
# --------------------------------------------------------------------------
class SlidingWindowLimiter:
    def __init__(self, window_seconds: int) -> None:
        self._window = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int) -> Optional[int]:
        """Record a hit. Returns seconds to wait if the limit is exceeded, else None."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 5000:
                self._prune(now)
            bucket = self._hits.setdefault(key, deque())
            while bucket and now - bucket[0] >= self._window:
                bucket.popleft()
            if len(bucket) >= limit:
                return max(1, int(self._window - (now - bucket[0])) + 1)
            bucket.append(now)
            return None

    def _prune(self, now: float) -> None:
        for key in [k for k, b in self._hits.items() if not b or now - b[-1] >= self._window]:
            del self._hits[key]


_limiters: dict[int, SlidingWindowLimiter] = {}
_limiters_lock = threading.Lock()


def reset_rate_limiters() -> None:
    with _limiters_lock:
        _limiters.clear()


def _get_limiter(window: int) -> SlidingWindowLimiter:
    with _limiters_lock:
        return _limiters.setdefault(window, SlidingWindowLimiter(window))


def enforce_upload_rate_limit(
    request: Request,
    session_id: str = Depends(get_session_id),
    settings: Settings = Depends(get_settings),
) -> None:
    limiter = _get_limiter(settings.rate_limit_window_seconds)
    # X-Forwarded-For is deliberately ignored: clients can spoof it.
    client_ip = request.client.host if request.client else "unknown"
    retry = limiter.hit(f"sid:{session_id}", settings.rate_limit_uploads)
    if retry is None:
        retry = limiter.hit(f"ip:{client_ip}", settings.rate_limit_uploads * 3)
    if retry is not None:
        raise HTTPException(
            status_code=429,
            detail="Too many uploads. Please wait a moment and try again.",
            headers={"Retry-After": str(retry)},
        )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _safe_filename(raw: Optional[str]) -> str:
    name = (raw or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()
    return name[:_MAX_FILENAME_LENGTH] or "upload.zip"


def _extract_report(row: Any) -> Optional[dict[str, Any]]:
    """Read report_json from a Scan row, whether stored as text or as a JSON column."""
    raw = row.get("report_json") if isinstance(row, dict) else getattr(row, "report_json", None)
    for _ in range(2):  # tolerate a double-encoded JSON string
        if isinstance(raw, (str, bytes, bytearray)):
            try:
                raw = json.loads(raw)
            except (ValueError, TypeError):
                return None
    return raw if isinstance(raw, dict) else None


def _created_at(row: Any) -> Optional[str]:
    value = row.get("created_at") if isinstance(row, dict) else getattr(row, "created_at", None)
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _valid_scan_id(scan_id: str) -> bool:
    try:
        return str(uuid.UUID(scan_id)) == scan_id.lower()
    except (ValueError, AttributeError, TypeError):
        return False


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------
@router.post("/upload", response_model=ScanReport)
def upload_scan(
    file: UploadFile = File(...),
    session_id: str = Depends(get_session_id),
    _rate: None = Depends(enforce_upload_rate_limit),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    explainer: AIExplainer = Depends(get_explainer),
    ruleset: RuleSet = Depends(get_ruleset),
) -> ScanReport:
    filename = _safe_filename(file.filename)
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files can be uploaded.")

    try:
        data = file.file.read(settings.max_upload_bytes + 1)
    finally:
        file.file.close()
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"The upload is larger than the {settings.max_upload_bytes // (1024 * 1024)} MB limit.",
        )

    try:
        inspection = inspect_zip(data, ZipLimits.from_settings(settings))
    except ZipRejected as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from None
    del data

    analysis = analyze(inspection.files, ruleset, settings.max_findings_per_rule)
    usage = explainer.enrich(analysis.findings, {r.id: r for r in ruleset.rules})

    counts = analysis.counts
    report = ScanReport(
        scan_id=str(uuid.uuid4()),
        filename=filename,
        overall_status="COMPLETED",
        counts=counts,
        findings=analysis.findings,
        verification_complete=(counts.not_verified == 0 and counts.failed == 0),
        official_rules_verified=ruleset.official_list_verified,
        ai=usage,
        stats=ScanStats(
            files_scanned=len(inspection.files),
            files_skipped=inspection.skipped,
            source_truncated=inspection.truncated,
        ),
    )

    try:
        create_scan(
            db,
            report.scan_id,
            session_id,
            filename,
            report.overall_status,
            json.dumps(report.model_dump(mode="json")),
        )
    except Exception as exc:  # noqa: BLE001 - never leak database errors to the client
        db.rollback()
        logger.error("Could not store scan %s (%s).", report.scan_id, type(exc).__name__)
        raise HTTPException(status_code=500, detail="The scan report could not be saved.") from None

    logger.info(
        "Scan %s complete: passed=%d failed=%d not_verified=%d ai_explanations=%d",
        report.scan_id, counts.passed, counts.failed, counts.not_verified, usage.explanations_ai,
    )
    return report


@router.get("", response_model=list[ScanSummary])
def list_session_scans(
    limit: int = Query(default=20, ge=1, le=100),
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db),
) -> list[ScanSummary]:
    try:
        rows = list_scans(db, session_id, limit=limit)
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.error("Could not list scans (%s).", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Scan history could not be loaded.") from None

    summaries: list[ScanSummary] = []
    for row in rows:
        report = _extract_report(row)
        if report is None:
            continue
        try:
            summaries.append(
                ScanSummary(
                    scan_id=report["scan_id"],
                    filename=report.get("filename", ""),
                    overall_status=report.get("overall_status", "COMPLETED"),
                    counts=report.get("counts"),
                    created_at=_created_at(row),
                )
            )
        except (KeyError, ValueError):
            continue
    return summaries


@router.get("/{scan_id}", response_model=ScanReport)
def get_session_scan(
    scan_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db),
) -> ScanReport:
    not_found = HTTPException(status_code=404, detail="Scan not found.")
    if not _valid_scan_id(scan_id):
        raise not_found
    try:
        row = get_scan(db, scan_id, session_id)
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.error("Could not load scan (%s).", type(exc).__name__)
        raise HTTPException(status_code=500, detail="The scan report could not be loaded.") from None
    if row is None:
        raise not_found  # same answer for "missing" and "belongs to another session"
    report = _extract_report(row)
    if report is None:
        logger.error("Stored report for scan %s is unreadable.", scan_id)
        raise HTTPException(status_code=500, detail="The scan report could not be loaded.")
    try:
        return ScanReport.model_validate(report)
    except ValueError:
        logger.error("Stored report for scan %s failed validation.", scan_id)
        raise HTTPException(status_code=500, detail="The scan report could not be loaded.") from None
