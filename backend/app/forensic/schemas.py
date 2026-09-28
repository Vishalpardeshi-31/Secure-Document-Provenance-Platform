from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field


class ForensicFingerprintResponse(BaseModel):
    """Metadata response for a recorded forensic fingerprint."""
    id: str
    document_id: str
    document_version_id: str
    provenance_event_id: str
    decryption_session_id: str
    viewer_session_id: str
    recipient_user_id: str
    recipient_key_id: Optional[str] = None
    fingerprint_version: int
    fingerprint_algorithm: str
    fingerprint_token: str
    fingerprint_commitment: str
    embedding_profile: str
    embedding_parameters_version: int
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProvenanceCorrelationInfo(BaseModel):
    """Cryptographic provenance verification correlated with the detected fingerprint."""
    event_id: str
    chain_id: str
    chain_sequence: int
    chain_hash: str
    previous_record_hash: str
    canonical_record_hash: str
    signature_algorithm: str
    signature_key_id: str
    signature_verified: bool
    chain_link_verified: bool
    ledger_anchored: bool
    ledger_transaction_id: Optional[str] = None
    ledger_hash_matched: bool
    event_timestamp: str

    model_config = ConfigDict(from_attributes=True)


class AssociatedSessionInfo(BaseModel):
    """Authorized viewing and decryption session associated with the detected fingerprint."""
    viewer_session_id: str
    decryption_session_id: str
    recipient_user_id: str
    recipient_username: str
    recipient_email: str
    recipient_department: Optional[str] = None
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    document_id: str
    document_title: Optional[str] = None
    document_version_id: str
    classification: str
    session_created_at: str
    session_expires_at: str
    session_status: str

    model_config = ConfigDict(from_attributes=True)


class ForensicDetectionResponse(BaseModel):
    """Result returned by the forensic detection and investigation service."""
    detection_status: str  # FINGERPRINT_DETECTED, NO_FINGERPRINT_DETECTED, UNSUPPORTED_EVIDENCE, PROCESSING_ERROR
    evidence_filename: str
    evidence_mime_type: Optional[str] = None
    fingerprint_version: Optional[int] = None
    embedding_profile: Optional[str] = None
    candidate_fingerprint_token: Optional[str] = None
    candidate_fingerprint_id: Optional[str] = None
    confidence_score: float = Field(0.0, ge=0.0, le=1.0)
    correlation: Optional[AssociatedSessionInfo] = None
    provenance: Optional[ProvenanceCorrelationInfo] = None
    diagnostics: Dict[str, Any] = Field(default_factory=dict)
    investigated_at: datetime
    investigating_user_id: str

    model_config = ConfigDict(from_attributes=True)


class TransformationRobustnessMetric(BaseModel):
    """Measured robustness metric for a specific transformation."""
    transformation_name: str
    description: str
    parameter_value: str
    detected: bool
    confidence_score: float
    bit_error_rate: float


class ForensicEvaluationReport(BaseModel):
    """Benchmark evaluation report containing experimentally measured robustness metrics."""
    test_run_id: str
    embedding_profile: str
    tested_document_format: str
    original_psnr_db: float
    unaltered_detection_success: bool
    false_detection_on_clean_document: bool
    transformations: List[TransformationRobustnessMetric]
    overall_detection_rate: float
    evaluated_at: datetime

    model_config = ConfigDict(from_attributes=True)
