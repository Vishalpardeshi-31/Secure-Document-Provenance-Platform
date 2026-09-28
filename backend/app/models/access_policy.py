import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Boolean, Integer, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base, TimestampMixin


class AccessPolicy(Base, TimestampMixin):
    __tablename__ = "access_policies"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    document_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    valid_from: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    valid_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expiration_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    device_restriction: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    require_registered_device: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    approval_requirement: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    require_approval: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    require_multi_party_approval: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    required_approvals: Mapped[int] = mapped_column(
        Integer, default=1, nullable=False
    )
    eligible_approver_roles: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    allow_emergency_access: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    eligible_emergency_roles: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    eligible_emergency_permission: Mapped[Optional[str]] = mapped_column(
        String(64), default="EMERGENCY_DECRYPT", nullable=True
    )
    emergency_approval_required: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    maximum_emergency_duration: Mapped[int] = mapped_column(
        Integer, default=15, nullable=False
    )
    maximum_sessions: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    max_decryptions: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    one_time_decryption: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    policy_version: Mapped[int] = mapped_column(
        Integer, default=1, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), default="ACTIVE", nullable=False, index=True
    )
    allowed_roles: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    consumed_decryptions: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    created_by: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    document: Mapped["Document"] = relationship("Document", back_populates="access_policies")  # noqa: F821
    decryption_sessions: Mapped[List["DecryptionSession"]] = relationship("DecryptionSession", back_populates="policy")  # noqa: F821
    approval_requests: Mapped[List["ApprovalRequest"]] = relationship("ApprovalRequest", back_populates="policy", cascade="all, delete-orphan")  # noqa: F821

