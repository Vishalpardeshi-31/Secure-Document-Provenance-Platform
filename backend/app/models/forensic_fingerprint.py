import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base


class ForensicFingerprint(Base):
    __tablename__ = "forensic_fingerprints"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    document_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    document_version_id: Mapped[str] = mapped_column(
        String(36), nullable=False, index=True
    )
    provenance_event_id: Mapped[str] = mapped_column(
        String(36), nullable=False, index=True
    )
    decryption_session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("decryption_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    viewer_session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("viewer_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    recipient_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    recipient_key_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True, index=True
    )
    fingerprint_version: Mapped[int] = mapped_column(
        Integer, default=1, nullable=False
    )
    fingerprint_algorithm: Mapped[str] = mapped_column(
        String(64), default="HKDF-SHA256-DSSS-DCT", nullable=False
    )
    fingerprint_token: Mapped[str] = mapped_column(
        String(32), unique=True, nullable=False, index=True
    )
    fingerprint_commitment: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    fingerprint_nonce: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    embedding_profile: Mapped[str] = mapped_column(
        String(64), default="PDF_DCT_SPREAD_SPECTRUM_V1", nullable=False
    )
    embedding_parameters_version: Mapped[int] = mapped_column(
        Integer, default=1, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), default="ACTIVE", nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    document: Mapped["Document"] = relationship("Document")  # noqa: F821
    decryption_session: Mapped["DecryptionSession"] = relationship("DecryptionSession")  # noqa: F821
    viewer_session: Mapped["ViewerSession"] = relationship("ViewerSession")  # noqa: F821
    recipient_user: Mapped["User"] = relationship("User")  # noqa: F821
