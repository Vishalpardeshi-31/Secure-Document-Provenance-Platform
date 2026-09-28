import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base, TimestampMixin


class Device(Base, TimestampMixin):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_name: Mapped[str] = mapped_column(
        String(128), nullable=False
    )
    device_fingerprint: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )
    registration_status: Mapped[str] = mapped_column(
        String(32), default="PENDING", nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(32), default="ACTIVE", nullable=False, index=True
    )
    device_identifier_hash: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )
    registered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    public_key: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )
    challenge_nonce: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    challenge_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="devices")  # noqa: F821
    decryption_sessions: Mapped[List["DecryptionSession"]] = relationship("DecryptionSession", back_populates="device")  # noqa: F821
