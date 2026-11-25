"""CRUD operations for scans. Every read is scoped by session_id."""

import json
import logging
import uuid
from typing import Any, List, Optional

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import Scan

logger = logging.getLogger(__name__)

MAX_LIMIT = 100
MAX_FILENAME_LEN = 255
MAX_SESSION_LEN = 128
MAX_STATUS_LEN = 32
MAX_REPORT_BYTES = 5 * 1024 * 1024  # 5 MB


class DatabaseError(Exception):
    """Safe error that never exposes connection details or SQL."""


def _require_text(value: Any, name: str, max_len: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required and must be a non-empty string")
    value = value.strip()
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


def _validate_uuid(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a UUID string")
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        raise ValueError(f"{name} must be a valid UUID string")


def _normalize_report(report_json: Any) -> str:
    """Store report content consistently as a compact JSON string."""
    if report_json is None:
        raise ValueError("report_json is required")
    if isinstance(report_json, (bytes, bytearray)):
        report_json = report_json.decode("utf-8")
    if isinstance(report_json, str):
        if not report_json.strip():
            raise ValueError("report_json is required")
        try:
            parsed = json.loads(report_json)
        except json.JSONDecodeError:
            raise ValueError("report_json must be valid JSON")
    else:
        parsed = report_json  # dict / list accepted and serialized
    try:
        text = json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        raise ValueError("report_json must be JSON serializable")
    if len(text.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("report_json is too large")
    return text


def create_scan(db: Session, scan_id, session_id, filename, status, report_json) -> Scan:
    scan_id = _validate_uuid(scan_id, "scan_id")
    session_id = _require_text(session_id, "session_id", MAX_SESSION_LEN)
    filename = _require_text(filename, "filename", MAX_FILENAME_LEN)
    status = _require_text(status, "status", MAX_STATUS_LEN)
    report_text = _normalize_report(report_json)

    scan = Scan(
        id=scan_id,
        session_id=session_id,
        filename=filename,
        status=status,
        report_json=report_text,
    )
    try:
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to create scan")
        raise DatabaseError("Could not save the scan")


def get_scan(db: Session, scan_id, session_id) -> Optional[Scan]:
    """Return the scan only if BOTH scan_id and session_id match."""
    if not isinstance(scan_id, str) or not isinstance(session_id, str):
        return None
    if not scan_id.strip() or not session_id.strip():
        return None
    try:
        stmt = select(Scan).where(
            Scan.id == scan_id.strip(),
            Scan.session_id == session_id.strip(),
        )
        return db.execute(stmt).scalars().first()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to fetch scan")
        raise DatabaseError("Could not read the scan")


def list_scans(db: Session, session_id, limit: int = 20) -> List[Scan]:
    """Return this session's scans only, newest first."""
    if not isinstance(session_id, str) or not session_id.strip():
        return []
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 20
    limit = max(1, min(limit, MAX_LIMIT))
    try:
        stmt = (
            select(Scan)
            .where(Scan.session_id == session_id.strip())
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .limit(limit)
        )
        return list(db.execute(stmt).scalars().all())
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to list scans")
        raise DatabaseError("Could not list scans")