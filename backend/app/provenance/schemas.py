"""Pydantic schemas for cryptographic provenance records, hash chain, and ledger verification."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class ProvenanceRecordResponse(BaseModel):
    """Public representation of a cryptographically signed provenance record."""
    id: str
    event_id: str
    document_id: Optional[str] = None
    document_version_id: Optional[str] = None
    user_id: Optional[str] = None
    recipient_key_id: Optional[str] = None
    recipient_key_version: Optional[int] = None
    device_id: Optional[str] = None
    decryption_session_id: Optional[str] = None
    policy_id: Optional[str] = None
    policy_version: Optional[int] = None
    access_type: str
    approval_request_id: Optional[str] = None
    emergency_access_request_id: Optional[str] = None
    document_plaintext_sha256: str
    document_ciphertext_sha256: str
    event_timestamp: str
    protocol_version: str
    provenance_version: int
    canonical_record_hash: str
    signature_algorithm: str
    signature_key_id: str
    signature_key_version: int
    signature: str

    # Phase 10: Provenance Chain Fields
    chain_id: str
    chain_sequence: int
    previous_record_hash: str
    chain_hash: str
    chain_version: int

    # Phase 10: Ledger Fields
    ledger_transaction_id: Optional[str] = None
    ledger_status: str
    ledger_record_hash: Optional[str] = None
    ledger_anchored_at: Optional[datetime] = None

    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProvenanceVerificationResponse(BaseModel):
    """Cryptographic verification result for a single provenance record."""
    event_id: str
    hash_valid: bool
    signature_valid: bool
    signing_key_version: int
    verified: bool
    reason: Optional[str] = None
    verified_at: str

    model_config = ConfigDict(from_attributes=True)


class ProvenanceSigningKeyResponse(BaseModel):
    """Public representation of a provenance signing key (public key material only)."""
    id: str
    key_version: int
    algorithm: str
    public_key: str
    status: str
    created_at: datetime
    activated_at: Optional[datetime] = None
    retired_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ProvenanceChainHeadResponse(BaseModel):
    """Tip status of a provenance hash chain."""
    chain_id: str
    latest_sequence: int
    latest_chain_hash: str
    genesis_hash: str
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProvenanceChainVerificationResponse(BaseModel):
    """Full-chain verification result auditing sequence continuity, hash linkage, signatures, and ledger anchors."""
    chain_valid: bool
    chain_id: str
    records_checked: int
    first_invalid_sequence: Optional[int] = None
    failure_type: Optional[str] = None  # SEQUENCE_GAP, PREVIOUS_HASH_MISMATCH, CHAIN_HASH_MISMATCH, SIGNATURE_INVALID, LEDGER_ANCHOR_MISMATCH, GENESIS_CORRUPTED
    failure_detail: Optional[str] = None
    signatures_verified: int
    ledger_anchors_verified: int
    verified_at: str

    model_config = ConfigDict(from_attributes=True)


class LedgerAnchorVerificationResponse(BaseModel):
    """Verification result for a record's anchor in the permissioned ledger."""
    event_id: str
    is_anchored: bool
    transaction_id: Optional[str] = None
    expected_chain_hash: str
    ledger_chain_hash: Optional[str] = None
    hash_matched: bool
    status: str  # CONFIRMED, MISMATCH, NOT_FOUND, FAILED
    details: Optional[str] = None
    anchored_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class LedgerOutboxProcessResponse(BaseModel):
    """Results from processing pending ledger outbox items."""
    processed: int
    confirmed: int
    failed: int

    model_config = ConfigDict(from_attributes=True)
