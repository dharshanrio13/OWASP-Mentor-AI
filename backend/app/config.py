"""Application configuration, read from environment variables.

No secrets are hardcoded here. Every value has a safe default and can be
overridden through the environment or a local ``.env`` file (never committed).
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

logger = logging.getLogger("owasp_mentor.config")

APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR.parent
REPO_ROOT = BACKEND_DIR.parent
RULES_PATH = APP_DIR / "security" / "rules.json"

# Load .env from the repo root first, then backend/. Real environment variables win.
for _env_file in (REPO_ROOT / ".env", BACKEND_DIR / ".env"):
    if _env_file.is_file():
        load_dotenv(_env_file, override=False)

MB = 1024 * 1024
_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        logger.warning("Ignoring invalid integer for %s; using default.", name)
        return default
    return max(minimum, min(maximum, value))


@dataclass(frozen=True)
class Settings:
    # --- AI (local Ollama only) -------------------------------------------
    ai_provider: str = "ollama"
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen3:4b"
    ai_enabled: bool = True
    ollama_allow_non_local: bool = False
    ai_request_timeout: float = 45.0
    ai_status_timeout: float = 3.0
    ai_total_budget: float = 120.0
    ai_max_explanations: int = 5

    # --- Web --------------------------------------------------------------
    frontend_origin: str = "http://localhost:5173"
    enable_docs: bool = False

    # --- ZIP limits -------------------------------------------------------
    max_upload_bytes: int = 10 * MB
    max_entries: int = 300
    max_total_uncompressed: int = 20 * MB
    max_file_bytes: int = 2 * MB
    max_compression_ratio: int = 100
    max_text_chars: int = 1_500_000

    # --- Scanner ----------------------------------------------------------
    max_findings_per_rule: int = 10

    # --- Rate limiting (in-memory, per process) ---------------------------
    rate_limit_uploads: int = 10
    rate_limit_window_seconds: int = 60

    @property
    def ollama_is_local(self) -> bool:
        try:
            host = (urlparse(self.ollama_base_url).hostname or "").lower()
        except ValueError:
            return False
        return host in _LOCAL_HOSTS

    @property
    def ollama_url_allowed(self) -> bool:
        return self.ollama_is_local or self.ollama_allow_non_local

    @property
    def request_body_limit(self) -> int:
        # Multipart framing adds a little overhead on top of the file itself.
        return self.max_upload_bytes + 1 * MB

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            ai_provider=os.getenv("AI_PROVIDER", "ollama").strip().lower(),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip().rstrip("/"),
            ollama_model=os.getenv("OLLAMA_MODEL", "qwen3:4b").strip(),
            ai_enabled=_get_bool("AI_ENABLED", True),
            ollama_allow_non_local=_get_bool("OLLAMA_ALLOW_NON_LOCAL", False),
            ai_request_timeout=float(_get_int("AI_REQUEST_TIMEOUT", 45, 5, 300)),
            ai_status_timeout=float(_get_int("AI_STATUS_TIMEOUT", 3, 1, 30)),
            ai_total_budget=float(_get_int("AI_TOTAL_BUDGET", 120, 10, 900)),
            ai_max_explanations=_get_int("AI_MAX_EXPLANATIONS", 5, 0, 13),
            frontend_origin=os.getenv("FRONTEND_ORIGIN", "http://localhost:5173").strip().rstrip("/"),
            enable_docs=_get_bool("ENABLE_DOCS", False),
            rate_limit_uploads=_get_int("RATE_LIMIT_UPLOADS", 10, 1, 1000),
            rate_limit_window_seconds=_get_int("RATE_LIMIT_WINDOW_SECONDS", 60, 1, 3600),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()
