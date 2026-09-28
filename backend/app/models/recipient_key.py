import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Text, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base


class RecipientKey(Base):
    """Stores versioned cryptographic public keys and protected private keys for recipients.
    
    Private keys are NEVER stored in plaintext. They are encrypted at rest using AES-256-GCM
    under a dedicated server-side master key-protection key (RECIPIENT_KEY_KEK).
    """
    __tablename__ = "recipient_keys"
    __table_args__ = (
        UniqueConstraint("user_id", "key_version", name="uq_recipient_key_user_version"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )
    algorithm: Mapped[str] = mapped_column(
        String(64), nullable=False, default="ML-KEM-768"
    )
    public_key: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    encrypted_private_key: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    kdf_algorithm: Mapped[str] = mapped_column(
        String(32), default="Argon2id", nullable=False
    )
    kdf_salt: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    kdf_parameters: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    encryption_algorithm: Mapped[str] = mapped_column(
        String(32), default="AES-256-GCM", nullable=False
    )
    encryption_nonce: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(32), default="ACTIVE", nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="recipient_keys")  # noqa: F821
