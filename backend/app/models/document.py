import uuid
from typing import List, Optional
from sqlalchemy import String, ForeignKey, BigInteger, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base, TimestampMixin


class Document(Base, TimestampMixin):
    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )
    original_filename: Mapped[str] = mapped_column(
        String(255), nullable=False, default=""
    )
    mime_type: Mapped[str] = mapped_column(
        String(128), nullable=False, default="application/octet-stream"
    )
    original_size_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    encrypted_size_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    storage_reference: Mapped[str] = mapped_column(
        String(512), nullable=False, default=""
    )
    plaintext_sha256: Mapped[str] = mapped_column(
        String(64), nullable=False, default=""
    )
    ciphertext_sha256: Mapped[str] = mapped_column(
        String(64), nullable=False, default=""
    )
    encryption_algorithm: Mapped[str] = mapped_column(
        String(64), default="AES-256-GCM", nullable=False
    )
    key_encryption_algorithm: Mapped[str] = mapped_column(
        String(64), default="AES-256-GCM-KEK", nullable=False
    )
    nonce: Mapped[str] = mapped_column(
        String(64), nullable=False, default=""
    )
    encrypted_dek: Mapped[str] = mapped_column(
        String(512), nullable=False, default=""
    )
    key_management_version: Mapped[int] = mapped_column(
        Integer, default=2, nullable=False
    )
    protocol_version: Mapped[str] = mapped_column(
        String(32), default="SDP-CRYPTO-V2", nullable=False
    )
    classification: Mapped[str] = mapped_column(
        String(32), default="RESTRICTED", nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(32), default="PENDING", nullable=False, index=True
    )

    # Relationships
    owner: Mapped["User"] = relationship("User", back_populates="documents")  # noqa: F821
    versions: Mapped[List["DocumentVersion"]] = relationship(  # noqa: F821
        "DocumentVersion", back_populates="document", cascade="all, delete-orphan", order_by="DocumentVersion.version_number"
    )
    recipients: Mapped[List["DocumentRecipient"]] = relationship(  # noqa: F821
        "DocumentRecipient", back_populates="document", cascade="all, delete-orphan"
    )
    access_policies: Mapped[List["AccessPolicy"]] = relationship(  # noqa: F821
        "AccessPolicy", back_populates="document", cascade="all, delete-orphan"
    )
    decryption_sessions: Mapped[List["DecryptionSession"]] = relationship(  # noqa: F821
        "DecryptionSession", back_populates="document"
    )
    audit_events: Mapped[List["AuditEvent"]] = relationship(  # noqa: F821
        "AuditEvent", back_populates="document"
    )
