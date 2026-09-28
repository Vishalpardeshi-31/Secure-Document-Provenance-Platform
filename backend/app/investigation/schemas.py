from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field


class InvestigationCaseCreateRequest(BaseModel):
    """Payload to initialize a new investigation case."""
    title: str = Field(..., min_length=3, max_length=255, description="Investigation case title or subject")
    description: Optional[str] = Field(None, max_length=2000, description="Context, source of leak, notes")
    document_id: Optional[str] = Field(None, description="Optional suspected source document ID if known")
    document_version_id: Optional[str] = Field(None, description="Optional document version ID")


class InvestigationCaseResponse(BaseModel):
    """Summary representation of an investigation case."""
    id: str
    case_reference: str
    title: str
    description: Optional[str] = None
    created_by: str
    document_id: Optional[str] = None
    document_version_id: Optional[str] = None
    evidence_filename: Optional[str] = None
    evidence_sha256: Optional[str] = None
    evidence_size: Optional[int] = None
    evidence_mime_type: Optional[str] = None
    status: str
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    evidence_count: int = 0
    results_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class InvestigationEvidenceResponse(BaseModel):
    """Metadata response for immutable evidence artifact."""
    id: str
    case_id: str
    original_filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    uploaded_by: str
    uploaded_at: datetime
    evidence_version: int
    processing_status: str

    model_config = ConfigDict(from_attributes=True)


class CustodyEventResponse(BaseModel):
    """Immutable audit record in the evidence chain of custody."""
    id: str
    case_id: str
    evidence_id: Optional[str] = None
    actor_id: str
    action: str
    evidence_sha256: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TimelineEvent(BaseModel):
    """Factual chronological event in the investigation timeline."""
    event_name: str
    timestamp: str
    actor_or_source: str
    description: str
    verification_status: Optional[str] = None


class InvestigationResultResponse(BaseModel):
    """Formal factual findings from forensic analysis and cryptographic verification."""
    id: str
    case_id: str
    evidence_id: str
    detection_status: str
    fingerprint_id: Optional[str] = None
    provenance_event_id: Optional[str] = None
    provenance_signature_status: Optional[str] = None
    chain_verification_status: Optional[str] = None
    ledger_verification_status: Optional[str] = None
    confidence_score: float = Field(0.0, ge=0.0, le=1.0)
    analyzed_at: datetime
    analyzer_version: str
    result_summary: str
    limitations: str
    details: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class InvestigationCaseDetailResponse(BaseModel):
    """Comprehensive case view with full evidence, chain of custody, and verified findings."""
    case: InvestigationCaseResponse
    evidence_items: List[InvestigationEvidenceResponse]
    custody_chain: List[CustodyEventResponse]
    results: List[InvestigationResultResponse]
    timeline: List[TimelineEvent]

    model_config = ConfigDict(from_attributes=True)


class InvestigationReportResponse(BaseModel):
    """Exportable formal investigation report containing evidence findings and cryptographic proofs."""
    report_id: str
    report_version: str
    case_reference: str
    case_title: str
    generated_at: datetime
    generated_by_user_id: str
    evidence_metadata: Dict[str, Any]
    evidence_sha256: str
    detection_status: str
    provenance_verification: Dict[str, Any]
    chain_verification: Dict[str, Any]
    ledger_verification: Dict[str, Any]
    factual_findings: str
    timeline: List[TimelineEvent]
    limitations_disclaimer: str
    report_sha256: str
