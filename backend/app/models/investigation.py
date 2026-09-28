import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import String, Integer, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base


class InvestigationCase(Base):
    """Investigation case container for forensic leak analysis."""
    __tablename__ = "investigation_cases"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    case_reference: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    created_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    document_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    document_version_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True
    )
    evidence_filename: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    evidence_sha256: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )
    evidence_size: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    evidence_mime_type: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(32), default="OPEN", nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    creator: Mapped["User"] = relationship("User", foreign_keys=[created_by])  # noqa: F821
    document: Mapped[Optional["Document"]] = relationship("Document", foreign_keys=[document_id])  # noqa: F821
    evidence_items: Mapped[List["InvestigationEvidence"]] = relationship(
        "InvestigationEvidence", back_populates="case", cascade="all, delete-orphan"
    )
    custody_events: Mapped[List["InvestigationCustodyEvent"]] = relationship(
        "InvestigationCustodyEvent", back_populates="case", cascade="all, delete-orphan", order_by="InvestigationCustodyEvent.created_at"
    )
    results: Mapped[List["InvestigationResult"]] = relationship(
        "InvestigationResult", back_populates="case", cascade="all, delete-orphan", order_by="InvestigationResult.analyzed_at"
    )


class InvestigationEvidence(Base):
    """Immutable evidence artifact deposited for forensic analysis."""
    __tablename__ = "investigation_evidence"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    original_filename: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    mime_type: Mapped[str] = mapped_column(
        String(128), nullable=False
    )
    size_bytes: Mapped[int] = mapped_column(
        Integer, nullable=False
    )
    sha256: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    storage_reference: Mapped[str] = mapped_column(
        String(512), nullable=False
    )
    uploaded_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    evidence_version: Mapped[int] = mapped_column(
        Integer, default=1, nullable=False
    )
    processing_status: Mapped[str] = mapped_column(
        String(32), default="PENDING", nullable=False, index=True
    )

    # Relationships
    case: Mapped["InvestigationCase"] = relationship("InvestigationCase", back_populates="evidence_items")
    uploader: Mapped["User"] = relationship("User", foreign_keys=[uploaded_by])  # noqa: F821
    custody_events: Mapped[List["InvestigationCustodyEvent"]] = relationship(
        "InvestigationCustodyEvent", back_populates="evidence", cascade="all, delete-orphan"
    )
    results: Mapped[List["InvestigationResult"]] = relationship(
        "InvestigationResult", back_populates="evidence", cascade="all, delete-orphan"
    )


class InvestigationCustodyEvent(Base):
    """Immutable chain of custody log record for evidence handling."""
    __tablename__ = "investigation_custody_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("investigation_evidence.id", ondelete="CASCADE"), nullable=True, index=True
    )
    actor_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    evidence_sha256: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    metadata_json: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    case: Mapped["InvestigationCase"] = relationship("InvestigationCase", back_populates="custody_events")
    evidence: Mapped[Optional["InvestigationEvidence"]] = relationship("InvestigationEvidence", back_populates="custody_events")
    actor: Mapped["User"] = relationship("User", foreign_keys=[actor_id])  # noqa: F821


class InvestigationResult(Base):
    """Factual forensic and cryptographic attribution findings."""
    __tablename__ = "investigation_results"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    detection_status: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    fingerprint_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("forensic_fingerprints.id", ondelete="SET NULL"), nullable=True, index=True
    )
    provenance_event_id: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )
    provenance_signature_status: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    chain_verification_status: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    ledger_verification_status: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    confidence_score: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )
    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    analyzer_version: Mapped[str] = mapped_column(
        String(32), default="FORENSIC-V12", nullable=False
    )
    result_summary: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    limitations: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    details_json: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )

    # Relationships
    case: Mapped["InvestigationCase"] = relationship("InvestigationCase", back_populates="results")
    evidence: Mapped["InvestigationEvidence"] = relationship("InvestigationEvidence", back_populates="results")
    fingerprint: Mapped[Optional["ForensicFingerprint"]] = relationship("ForensicFingerprint", foreign_keys=[fingerprint_id])  # noqa: F821
