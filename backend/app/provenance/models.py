"""Database entities for cryptographic provenance records and signing keys."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    Text,
    DateTime,
    ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from app.database.base import Base


class ProvenanceSigningKey(Base):
    """Dedicated post-quantum ML-DSA signing keys for cryptographic provenance.
    
    Security Guarantee:
    - Never reuses recipient ML-KEM keys or document DEKs.
    - Private key is encrypted at rest using server-side AES-256-GCM.
    - Versioned to ensure historical provenance records remain verifiable after rotation.
    - Exactly one key is ACTIVE at any time.
    """
    __tablename__ = "provenance_signing_keys"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key_version = Column(Integer, nullable=False, unique=True, index=True)
    algorithm = Column(String(32), nullable=False, default="ML-DSA-65")
    public_key = Column(Text, nullable=False)  # PEM SubjectPublicKeyInfo
    encrypted_private_key = Column(Text, nullable=False)  # JSON payload: AES-256-GCM protected
    status = Column(String(16), nullable=False, default="ACTIVE", index=True)  # ACTIVE, RETIRED, REVOKED
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    activated_at = Column(DateTime(timezone=True), nullable=True)
    retired_at = Column(DateTime(timezone=True), nullable=True)


class ProvenanceRecord(Base):
    """Cryptographically signed, immutable record of an authorized document decryption event.
    
    Security Guarantee:
    - Deterministically canonicalized and signed using post-quantum ML-DSA-65.
    - Chained to previous provenance record via SHA-256 hash chaining.
    - Monotonically sequence-numbered under concurrency protection.
    - Anchored into a tamper-evident append-only ledger.
    - Immutable: records are write-once and can never be modified through APIs.
    - Does NOT store plaintext, DEK, recipient private key, or shared secrets.
    """
    __tablename__ = "provenance_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String(36), nullable=False, unique=True, index=True, default=lambda: str(uuid.uuid4()))
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=True, index=True)
    document_version_id = Column(String(36), nullable=True, index=True)

    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    recipient_key_id = Column(String(36), nullable=True)
    recipient_key_version = Column(Integer, nullable=True)

    device_id = Column(String(36), nullable=True)
    decryption_session_id = Column(String(36), nullable=True, index=True)

    policy_id = Column(String(36), nullable=True)
    policy_version = Column(Integer, nullable=True)

    access_type = Column(String(32), nullable=False, default="NORMAL", index=True)  # NORMAL, MULTI_PARTY_APPROVED, EMERGENCY
    approval_request_id = Column(String(36), nullable=True)
    emergency_access_request_id = Column(String(36), nullable=True)

    document_plaintext_sha256 = Column(String(64), nullable=False)
    document_ciphertext_sha256 = Column(String(64), nullable=False)

    event_timestamp = Column(String(32), nullable=False)  # Normalized ISO-8601 UTC string: YYYY-MM-DDTHH:MM:SS.ffffffZ
    protocol_version = Column(String(32), nullable=False, default="PROVENANCE-V1")
    provenance_version = Column(Integer, nullable=False, default=1)

    canonical_record_hash = Column(String(64), nullable=False)  # Hex SHA-256 of canonical bytes
    signature_algorithm = Column(String(32), nullable=False, default="ML-DSA-65")
    signature_key_id = Column(String(36), nullable=False)
    signature_key_version = Column(Integer, nullable=False)
    signature = Column(Text, nullable=False)  # Base64 ML-DSA-65 signature

    # Phase 10: Provenance Chain Fields
    chain_id = Column(String(64), nullable=False, default="PLATFORM-PROVENANCE-CHAIN", index=True)
    chain_sequence = Column(Integer, nullable=False, index=True)
    previous_record_hash = Column(String(64), nullable=False)
    chain_hash = Column(String(64), nullable=False, index=True)
    chain_version = Column(Integer, nullable=False, default=1)

    # Phase 10: Ledger Anchoring Fields
    ledger_transaction_id = Column(String(128), nullable=True, index=True)
    ledger_status = Column(String(32), nullable=False, default="PENDING", index=True)  # PENDING, CONFIRMED, FAILED
    ledger_record_hash = Column(String(64), nullable=True)
    ledger_anchored_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("chain_id", "chain_sequence", name="uq_provenance_chain_sequence"),
        UniqueConstraint("chain_id", "chain_hash", name="uq_provenance_chain_hash"),
    )

    # Relationships
    document = relationship("Document", backref="provenance_records")
    user = relationship("User", backref="provenance_records")


class ProvenanceChainHead(Base):
    """Verifiable chain head tracking the latest sequence and tip hash of each provenance chain."""
    __tablename__ = "provenance_chain_heads"

    chain_id = Column(String(64), primary_key=True)
    latest_sequence = Column(Integer, nullable=False, default=0)
    latest_chain_hash = Column(String(64), nullable=False)
    genesis_hash = Column(String(64), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class LedgerOutbox(Base):
    """Reliable transactional outbox for permissioned ledger anchoring."""
    __tablename__ = "ledger_outbox"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    outbox_id = Column(String(36), nullable=False, unique=True, index=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String(36), nullable=False, index=True)
    chain_id = Column(String(64), nullable=False, index=True)
    chain_sequence = Column(Integer, nullable=False)
    chain_hash = Column(String(64), nullable=False)
    payload_json = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="PENDING", index=True)  # PENDING, SUBMITTED, CONFIRMED, FAILED
    attempt_count = Column(Integer, nullable=False, default=0)
    max_retries = Column(Integer, nullable=False, default=5)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)

