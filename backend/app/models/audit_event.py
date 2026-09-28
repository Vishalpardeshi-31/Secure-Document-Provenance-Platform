import uuid
from datetime import datetime, timezone
from typing import Optional, Any, Dict
from sqlalchemy import String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    event_type: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    user_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    document_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    session_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("decryption_sessions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    event_hash: Mapped[str] = mapped_column(
        String(128), nullable=False
    )
    previous_event_hash: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )
    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", back_populates="audit_events")  # noqa: F821
    document: Mapped[Optional["Document"]] = relationship("Document", back_populates="audit_events")  # noqa: F821
    session: Mapped[Optional["DecryptionSession"]] = relationship("DecryptionSession", back_populates="audit_events")  # noqa: F821
