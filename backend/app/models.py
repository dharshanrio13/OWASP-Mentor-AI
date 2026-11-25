"""SQLAlchemy models for OWASP Mentor AI."""

from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, Column, DateTime, Index, String, Text

from app.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, nullable=False)  # UUID string
    session_id = Column(String(128), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    status = Column(String(32), nullable=False)
    report_json = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        CheckConstraint("length(id) = 36", name="ck_scans_id_len"),
        CheckConstraint("length(session_id) > 0", name="ck_scans_session_nonempty"),
        CheckConstraint("length(filename) > 0", name="ck_scans_filename_nonempty"),
        CheckConstraint("length(status) > 0", name="ck_scans_status_nonempty"),
        Index("ix_scans_session_created", "session_id", "created_at"),
    )

    def __repr__(self) -> str:  # never include report content
        return f"<Scan id={self.id} status={self.status}>"