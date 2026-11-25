"""Database configuration for OWASP Mentor AI.

Exports: Base, engine, SessionLocal, get_db
"""

import logging
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

logger = logging.getLogger(__name__)

# backend/app/database.py -> parents[1] == backend/
BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "owasp_mentor.db"
DATABASE_URL = f"sqlite:///{DB_PATH.as_posix()}"

engine = create_engine(
    DATABASE_URL,
    # Required for SQLite when FastAPI serves requests from a threadpool.
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
    future=True,
)


@event.listens_for(Engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Enable foreign keys and a busy timeout for every SQLite connection."""
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()
    except Exception:  # pragma: no cover - defensive, never leak details
        logger.exception("Failed to set SQLite pragmas")


SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    future=True,
)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yields a session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()