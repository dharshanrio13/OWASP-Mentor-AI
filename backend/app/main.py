"""OWASP Mentor AI backend entry point.

Run from the ``backend`` directory:  uvicorn app.main:app --reload --port 8000
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import Settings, get_settings
from app.database import Base, SessionLocal, engine, get_db  # noqa: F401 - agreed interface
from app.models import Scan  # noqa: F401 - registers the table on Base.metadata
from app.routers import scans
from app.schemas import AIStatus, HealthResponse, RuleSet, RulesResponse
from app.services.ai_explainer import AIExplainer, get_explainer
from app.services.scanner import get_ruleset

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("owasp_mentor")


class BodySizeLimitMiddleware:
    """Reject oversized request bodies, using Content-Length and a streaming byte count."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                response = JSONResponse({"detail": "Invalid Content-Length header."}, status_code=400)
                await response(scope, receive, send)
                return
            if too_big:
                response = JSONResponse({"detail": "The request body is too large."}, status_code=413)
                await response(scope, receive, send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # HTTPException is handled by FastAPI and becomes a clean 413.
                    raise HTTPException(status_code=413, detail="The request body is too large.")
            return message

        await self.app(scope, limited_receive, send)


class SecurityHeadersMiddleware:
    """Add conservative security headers to every response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                for name, value in (
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store"),
                ):
                    if name not in present:
                        headers.append((name, value))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    Base.metadata.create_all(bind=engine)  # idempotent database initialisation
    ruleset = get_ruleset()  # fail fast on an invalid rules file
    settings = get_settings()
    logger.info(
        "Started with %d rules (official list verified: %s). AI provider=%s model=%s enabled=%s",
        len(ruleset.rules), ruleset.official_list_verified,
        settings.ai_provider, settings.ollama_model, settings.ai_enabled,
    )
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    docs = settings.enable_docs
    app = FastAPI(
        title="OWASP Mentor AI",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
    )

    # Added last = outermost. CORS must wrap everything so errors carry CORS headers.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.request_body_limit)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.frontend_origin],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-Session-ID"],
    )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        errors: list[dict[str, Any]] = [
            {"loc": [str(part) for part in err.get("loc", [])], "msg": str(err.get("msg", "Invalid value"))}
            for err in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": "Invalid request.", "errors": errors})

    @app.exception_handler(Exception)
    async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        logger.error("Unhandled %s on %s %s", type(exc).__name__, request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error."})

    @app.get("/api/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        return HealthResponse()

    @app.get("/api/rules", response_model=RulesResponse, tags=["rules"])
    def rules(ruleset: RuleSet = Depends(get_ruleset)) -> RulesResponse:
        return RulesResponse(
            official_list_verified=ruleset.official_list_verified,
            notice=ruleset.notice,
            count=len(ruleset.rules),
            rules=ruleset.rules,
        )

    @app.get("/api/ai/status", response_model=AIStatus, tags=["ai"])
    def ai_status(explainer: AIExplainer = Depends(get_explainer)) -> AIStatus:
        return explainer.status()

    app.include_router(scans.router)
    return app


app = create_app()
