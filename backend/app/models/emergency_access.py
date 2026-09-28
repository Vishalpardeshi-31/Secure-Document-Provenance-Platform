"""Models for Emergency Break-Glass Access Workflow."""
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base


class EmergencyAccessRequest(Base):
    """Tracks emergency break-glass access requests with mandatory independent authorization."""
    __tablename__ = "emergency_access_requests"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    document_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requester_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requester_role: Mapped[str] = mapped_column(
        String(32), nullable=False
    )
    reason: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), default="REQUESTED", nullable=False, index=True
    )  # REQUESTED, AUTHORIZED, USED, EXPIRED, REJECTED, REVOKED
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    approver_user_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    rejection_reason: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )

    # Relationships
    document: Mapped["Document"] = relationship("Document")  # noqa: F821
    requester: Mapped["User"] = relationship("User", foreign_keys=[requester_user_id])  # noqa: F821
    approver: Mapped[Optional["User"]] = relationship("User", foreign_keys=[approver_user_id])  # noqa: F821
