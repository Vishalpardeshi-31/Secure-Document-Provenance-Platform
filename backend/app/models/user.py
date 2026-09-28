import uuid
from typing import Optional, List
from sqlalchemy import String, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base, TimestampMixin
from app.models.role import UserRole


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    password_hash: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    role: Mapped[str] = mapped_column(
        String(32), default=UserRole.RECIPIENT.value, nullable=False, index=True
    )
    role_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True
    )
    department_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("departments.id", ondelete="SET NULL"), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    can_emergency_decrypt: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    # Relationships
    role_rel: Mapped[Optional["Role"]] = relationship("Role", back_populates="users")  # noqa: F821
    department: Mapped[Optional["Department"]] = relationship("Department", back_populates="users")  # noqa: F821
    devices: Mapped[List["Device"]] = relationship("Device", back_populates="user", cascade="all, delete-orphan")  # noqa: F821
    recipient_keys: Mapped[List["RecipientKey"]] = relationship("RecipientKey", back_populates="user", cascade="all, delete-orphan")  # noqa: F821
    documents: Mapped[List["Document"]] = relationship("Document", back_populates="owner", cascade="all, delete-orphan")  # noqa: F821
    decryption_sessions: Mapped[List["DecryptionSession"]] = relationship("DecryptionSession", back_populates="user")  # noqa: F821
    audit_events: Mapped[List["AuditEvent"]] = relationship("AuditEvent", back_populates="user")  # noqa: F821

