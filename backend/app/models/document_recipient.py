import uuid
from typing import Optional
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Text, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base


class DocumentRecipient(Base):
    """Represents a recipient authorized to decrypt a document.
    
    Contains the recipient-specific key encapsulation material:
    - ML-KEM ciphertext (encapsulated_key)
    - AES-256-GCM wrapped DEK
    - GCM nonce
    - Version of the recipient's key used at encryption time
    """
    __tablename__ = "document_recipients"
    __table_args__ = (
        UniqueConstraint("document_id", "user_id", name="uq_document_recipient_user"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    document_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    permission_level: Mapped[str] = mapped_column(
        String(32), default="READ", nullable=False
    )
    recipient_key_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("recipient_keys.id", ondelete="SET NULL"), nullable=True, index=True
    )
    recipient_key_version: Mapped[int] = mapped_column(
        Integer, default=1, nullable=False
    )
    key_algorithm: Mapped[str] = mapped_column(
        String(64), default="ML-KEM-768+HKDF-SHA256+AES-256-GCM", nullable=False
    )
    kem_algorithm: Mapped[str] = mapped_column(
        String(32), default="ML-KEM-768", nullable=False
    )
    kem_ciphertext: Mapped[str] = mapped_column(
        Text, default="", nullable=False
    )
    kdf_algorithm: Mapped[str] = mapped_column(
        String(32), default="HKDF", nullable=False
    )
    kdf_hash: Mapped[str] = mapped_column(
        String(32), default="SHA-256", nullable=False
    )
    kdf_info_version: Mapped[str] = mapped_column(
        String(32), default="SDP-DEK-WRAP-v1", nullable=False
    )
    wrap_algorithm: Mapped[str] = mapped_column(
        String(32), default="AES-256-GCM", nullable=False
    )
    encapsulated_key: Mapped[str] = mapped_column(
        Text, default="", nullable=False
    )
    wrapped_dek: Mapped[str] = mapped_column(
        String(512), default="", nullable=False
    )
    nonce: Mapped[str] = mapped_column(
        String(64), default="", nullable=False
    )
    wrap_nonce: Mapped[str] = mapped_column(
        String(64), default="", nullable=False
    )
    protocol_version: Mapped[str] = mapped_column(
        String(32), default="SDP-CRYPTO-V2", nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), default="ACTIVE", nullable=False, index=True
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    document: Mapped["Document"] = relationship("Document", back_populates="recipients")  # noqa: F821
    user: Mapped["User"] = relationship("User")  # noqa: F821
    recipient_key: Mapped[Optional["RecipientKey"]] = relationship("RecipientKey")  # noqa: F821
