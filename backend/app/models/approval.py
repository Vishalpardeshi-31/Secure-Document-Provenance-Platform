"""Models for Multi-Party Approval Workflow."""
import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base


class ApprovalRequest(Base):
    """Tracks the multi-party approval lifecycle for a document decryption request."""
    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    document_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requesting_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    decryption_session_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("decryption_sessions.id", ondelete="SET NULL"), nullable=True
    )
    policy_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("access_policies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    policy_version: Mapped[int] = mapped_column(
        Integer, default=1, nullable=False
    )
    required_approvals: Mapped[int] = mapped_column(
        Integer, default=2, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), default="PENDING", nullable=False, index=True
    )  # PENDING, APPROVED, REJECTED, EXPIRED, CANCELLED
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    document: Mapped["Document"] = relationship("Document")  # noqa: F821
    requesting_user: Mapped["User"] = relationship("User", foreign_keys=[requesting_user_id])  # noqa: F821
    decryption_session: Mapped[Optional["DecryptionSession"]] = relationship("DecryptionSession")  # noqa: F821
    policy: Mapped["AccessPolicy"] = relationship("AccessPolicy", back_populates="approval_requests")  # noqa: F821
    records: Mapped[List["ApprovalRecord"]] = relationship(
        "ApprovalRecord", back_populates="approval_request", cascade="all, delete-orphan", order_by="ApprovalRecord.created_at"
    )


class ApprovalRecord(Base):
    """Tracks an individual approver's immutable decision record."""
    __tablename__ = "approval_records"
    __table_args__ = (
        UniqueConstraint("approval_request_id", "approver_user_id", name="uq_approval_request_approver"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    approval_request_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("approval_requests.id", ondelete="CASCADE"), nullable=False, index=True
    )
    approver_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    approver_role: Mapped[str] = mapped_column(
        String(32), nullable=False
    )
    decision: Mapped[str] = mapped_column(
        String(16), nullable=False
    )  # APPROVED, REJECTED
    reason: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Relationships
    approval_request: Mapped["ApprovalRequest"] = relationship("ApprovalRequest", back_populates="records")
    approver: Mapped["User"] = relationship("User", foreign_keys=[approver_user_id])  # noqa: F821
