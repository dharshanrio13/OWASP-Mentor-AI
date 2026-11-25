"""Shared test fixtures.

Tests use the real ``app.database.Base``, ``app.models.Scan`` and ``app.crud``
functions, but bind them to a throwaway in-memory SQLite engine so the real
database file is never touched. Uploaded code is only ever read as text.
"""
from __future__ import annotations

import io
import json
import uuid
import zipfile
from typing import Iterator, Optional, Union

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import Settings, get_settings
from app.database import Base, get_db
from app.main import create_app
from app.routers import scans as scans_router
from app.schemas import RuleDefinition, RuleSet
from app.services.ai_explainer import AIExplainer, get_explainer
from app.services.scanner import get_ruleset

import app.models  # noqa: F401  (registers tables on Base.metadata)


def make_zip(files: dict[str, Union[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def rule(**overrides: object) -> RuleDefinition:
    base: dict[str, object] = {
        "id": "TEST-01",
        "title": "Test rule",
        "description": "Test description of the problem.",
        "severity": "HIGH",
        "enabled": True,
        "check_type": "regex_finding",
        "extensions": [".js"],
        "pattern": r"\beval\s*\(",
        "recommendation": "Avoid eval and use a safe alternative.",
    }
    base.update(overrides)
    return RuleDefinition.model_validate(base)


def sample_ruleset() -> RuleSet:
    """Enabled test rules (NOT the official organizer list)."""
    return RuleSet(
        official_list_verified=False,
        notice="test rules",
        rules=[
            rule(id="TEST-01", title="No eval", check_type="regex_finding", pattern=r"\beval\s*\("),
            rule(id="TEST-02", title="Uses helmet", check_type="regex_required", pattern=r"helmet", severity="MEDIUM"),
            rule(id="TEST-03", title="Manual review", check_type="manual", pattern="", extensions=[]),
            rule(id="TEST-04", title="No document.write", check_type="regex_finding", pattern=r"document\.write", severity="LOW"),
            rule(id="TEST-05", title="Disabled rule", enabled=False, check_type="manual", pattern="", extensions=[]),
        ],
    )


def ollama_transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _reset_rate_limits() -> Iterator[None]:
    scans_router.reset_rate_limiters()
    yield
    scans_router.reset_rate_limiters()


@pytest.fixture()
def settings() -> Settings:
    return Settings(ai_enabled=False, rate_limit_uploads=1000)


@pytest.fixture()
def db_session_factory():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    yield factory
    engine.dispose()


@pytest.fixture()
def make_client(db_session_factory, settings):
    def _make(
        *,
        ruleset: Optional[RuleSet] = None,
        explainer: Optional[AIExplainer] = None,
        app_settings: Optional[Settings] = None,
    ) -> TestClient:
        s = app_settings or settings
        app = create_app()

        def override_db():
            db = db_session_factory()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_settings] = lambda: s
        app.dependency_overrides[get_explainer] = lambda: explainer or AIExplainer(s)
        if ruleset is not None:
            app.dependency_overrides[get_ruleset] = lambda: ruleset
        return TestClient(app, raise_server_exceptions=False)

    return _make


@pytest.fixture()
def client(make_client) -> TestClient:
    """Client using the shipped placeholder rules.json."""
    return make_client()


@pytest.fixture()
def session_id() -> str:
    return str(uuid.uuid4())


def upload(client: TestClient, data: bytes, session: str, filename: str = "project.zip"):
    return client.post(
        "/api/scans/upload",
        files={"file": (filename, data, "application/zip")},
        headers={"X-Session-ID": session},
    )


def ollama_chat_reply(payload: dict) -> httpx.Response:
    return httpx.Response(200, json={"message": {"role": "assistant", "content": json.dumps(payload)}})
