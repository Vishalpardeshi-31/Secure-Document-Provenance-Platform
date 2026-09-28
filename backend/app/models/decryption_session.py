import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base


class DecryptionSession(Base):
    __tablename__ = "decryption_sessions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    document_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("document_versions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    policy_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("access_policies.id", ondelete="SET NULL"), nullable=True
    )
    policy_version: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    session_token_hash: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(32), default="REQUESTED", nullable=False, index=True
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    authorized_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ended_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    failure_reason_code: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )

    # Relationships
    document: Mapped["Document"] = relationship("Document", back_populates="decryption_sessions")  # noqa: F821
    version: Mapped["DocumentVersion"] = relationship("DocumentVersion", back_populates="decryption_sessions")  # noqa: F821
    user: Mapped["User"] = relationship("User", back_populates="decryption_sessions")  # noqa: F821
    device: Mapped[Optional["Device"]] = relationship("Device", back_populates="decryption_sessions")  # noqa: F821
    policy: Mapped[Optional["AccessPolicy"]] = relationship("AccessPolicy", back_populates="decryption_sessions")  # noqa: F821
    audit_events: Mapped[List["AuditEvent"]] = relationship("AuditEvent", back_populates="session")  # noqa: F821
