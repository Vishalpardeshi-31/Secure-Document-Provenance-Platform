import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base


class ViewerSession(Base):
    __tablename__ = "viewer_sessions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    decryption_session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("decryption_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provenance_event_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True, index=True
    )
    document_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    document_version_id: Mapped[str] = mapped_column(
        String(36), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(
        String(32), default="ACTIVE", nullable=False, index=True
    )
    session_duration_seconds: Mapped[int] = mapped_column(
        Integer, default=900, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    decryption_session: Mapped["DecryptionSession"] = relationship("DecryptionSession")  # noqa: F821
    document: Mapped["Document"] = relationship("Document")  # noqa: F821
    user: Mapped["User"] = relationship("User")  # noqa: F821
    device: Mapped[Optional["Device"]] = relationship("Device")  # noqa: F821
