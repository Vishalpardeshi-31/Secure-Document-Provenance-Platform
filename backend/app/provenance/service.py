"""High-level provenance service orchestrating canonicalization, hashing, signing, hash chaining, and ledger anchoring."""
import uuid
import hashlib
import threading
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.user import User
from app.models.role import UserRole
from app.models.document import Document
from app.services.audit_service import AuditService
from app.provenance.models import ProvenanceRecord, ProvenanceSigningKey, ProvenanceChainHead, LedgerOutbox
from app.provenance.canonicalization import CanonicalizationService
from app.provenance.hashing import ProvenanceHashService
from app.provenance.signing import ProvenanceSigningService
from app.provenance.verification import ProvenanceVerificationService
from app.provenance.chain import ProvenanceChainService
from app.provenance.schemas import (
    ProvenanceVerificationResponse,
    ProvenanceChainHeadResponse,
    ProvenanceChainVerificationResponse,
    LedgerAnchorVerificationResponse,
    LedgerOutboxProcessResponse,
)
from app.provenance.exceptions import ProvenanceError
from app.ledger.service import LedgerService

logger = logging.getLogger("secure_document_platform.provenance")


class ProvenanceService:
    """Core cryptographic provenance service managing the end-to-end provenance lifecycle."""

    DEFAULT_CHAIN_ID = "PLATFORM-PROVENANCE-CHAIN"
    _chain_lock = threading.Lock()

    @classmethod
    def ensure_active_signing_key(cls, db: Session) -> ProvenanceSigningKey:
        """Ensures an active ML-DSA-65 provenance signing key exists."""
        return ProvenanceSigningService.get_or_create_active_key(db)

    @classmethod
    def rotate_signing_key(cls, db: Session, admin_user: User) -> ProvenanceSigningKey:
        """Rotates the active provenance signing key. Only authorized ADMINs may rotate keys."""
        if admin_user.role != UserRole.ADMIN.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators are authorized to rotate cryptographic provenance signing keys.",
            )

        new_key = ProvenanceSigningService.rotate_signing_key(db)

        # Audit event
        AuditService.log_event(
            db=db,
            event_type="PROVENANCE_KEY_ROTATED",
            user_id=admin_user.id,
            metadata={
                "new_key_id": new_key.id,
                "new_key_version": new_key.key_version,
                "algorithm": new_key.algorithm,
            },
        )
        return new_key

    @classmethod
    def list_signing_keys(cls, db: Session, requesting_user: User) -> List[ProvenanceSigningKey]:
        """Lists historical and active provenance public keys. Restricted to authorized roles."""
        if requesting_user.role not in [UserRole.ADMIN.value, UserRole.OFFICER.value, UserRole.AUDITOR.value]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unauthorized to inspect provenance signing key inventory.",
            )

        return (
            db.query(ProvenanceSigningKey)
            .order_by(ProvenanceSigningKey.key_version.desc())
            .all()
        )

    @classmethod
    def ensure_genesis(cls, db: Session, chain_id: str = DEFAULT_CHAIN_ID) -> ProvenanceChainHead:
        """Ensures the deterministic genesis record (sequence 0) and chain head exist."""
        head = db.query(ProvenanceChainHead).filter(ProvenanceChainHead.chain_id == chain_id).first()
        if head:
            return head

        genesis_record = (
            db.query(ProvenanceRecord)
            .filter(ProvenanceRecord.chain_id == chain_id, ProvenanceRecord.chain_sequence == 0)
            .first()
        )

        if not genesis_record:
            genesis_event_id = f"GENESIS-{chain_id}"
            genesis_canonical_hash = hashlib.sha256(f"PROVENANCE-GENESIS:{chain_id}:0".encode("utf-8")).hexdigest().lower()
            genesis_prev_hash = "0" * 64
            genesis_chain_hash = ProvenanceChainService.calculate_chain_hash(
                chain_id=chain_id,
                chain_sequence=0,
                previous_record_hash=genesis_prev_hash,
                canonical_record_hash=genesis_canonical_hash,
                event_id=genesis_event_id,
            )

            now_iso = "2026-01-01T00:00:00.000000Z"
            genesis_record = ProvenanceRecord(
                id=str(uuid.uuid4()),
                event_id=genesis_event_id,
                document_id=None,
                document_version_id="0",
                user_id=None,
                recipient_key_id=None,
                recipient_key_version=None,
                device_id=None,
                decryption_session_id=None,
                policy_id="GENESIS",
                policy_version=0,
                access_type="GENESIS",
                approval_request_id=None,
                emergency_access_request_id=None,
                document_plaintext_sha256="0" * 64,
                document_ciphertext_sha256="0" * 64,
                event_timestamp=now_iso,
                protocol_version="PROVENANCE-CHAIN-V1",
                provenance_version=1,
                canonical_record_hash=genesis_canonical_hash,
                signature_algorithm="SYSTEM-GENESIS",
                signature_key_id="GENESIS",
                signature_key_version=0,
                signature="SYSTEM-GENESIS-RECORD",
                chain_id=chain_id,
                chain_sequence=0,
                previous_record_hash=genesis_prev_hash,
                chain_hash=genesis_chain_hash,
                chain_version=1,
                ledger_transaction_id=f"TX-GENESIS-00000000-{genesis_chain_hash[:16].upper()}",
                ledger_status="CONFIRMED",
                ledger_record_hash=genesis_chain_hash,
                ledger_anchored_at=datetime.now(timezone.utc),
                created_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            )
            db.add(genesis_record)
            db.flush()

            # Anchor genesis in ledger adapter
            try:
                LedgerService.anchor_record({
                    "chain_id": chain_id,
                    "chain_sequence": 0,
                    "chain_hash": genesis_chain_hash,
                    "event_id": genesis_event_id,
                    "canonical_record_hash": genesis_canonical_hash,
                    "previous_record_hash": genesis_prev_hash,
                    "signature_algorithm": "SYSTEM-GENESIS",
                    "signature_key_version": 0,
                    "signature": "SYSTEM-GENESIS-RECORD",
                    "event_timestamp": now_iso,
                })
            except Exception as exc:
                logger.warning("Genesis ledger anchoring deferred: %s", exc)

        head = ProvenanceChainHead(
            chain_id=chain_id,
            latest_sequence=0,
            latest_chain_hash=genesis_record.chain_hash,
            genesis_hash=genesis_record.chain_hash,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(head)
        db.commit()
        db.refresh(head)
        return head

    @classmethod
    def record_decryption_provenance(
        cls,
        db: Session,
        *,
        document_id: str,
        document_version_id: str,
        user_id: str,
        recipient_key_id: Optional[str],
        recipient_key_version: Optional[int],
        device_id: Optional[str],
        decryption_session_id: str,
        policy_id: str,
        policy_version: int,
        access_type: str,
        approval_request_id: Optional[str] = None,
        emergency_access_request_id: Optional[str] = None,
        document_plaintext_sha256: str,
        document_ciphertext_sha256: str,
        chain_id: str = DEFAULT_CHAIN_ID,
    ) -> ProvenanceRecord:
        """Generates, signs, hash-chains, and ledger-anchors a provenance record for a successful decryption."""
        now = datetime.now(timezone.utc)
        event_id = str(uuid.uuid4())
        event_ts_str = CanonicalizationService.normalize_timestamp(now)

        # Step 1: Canonicalize event record
        canonical_bytes = CanonicalizationService.canonicalize_provenance_record(
            event_id=event_id,
            document_id=document_id,
            document_version_id=document_version_id,
            user_id=user_id,
            recipient_key_id=recipient_key_id,
            recipient_key_version=recipient_key_version,
            device_id=device_id,
            decryption_session_id=decryption_session_id,
            policy_id=policy_id,
            policy_version=policy_version,
            access_type=access_type,
            approval_request_id=approval_request_id,
            emergency_access_request_id=emergency_access_request_id,
            document_plaintext_sha256=document_plaintext_sha256,
            document_ciphertext_sha256=document_ciphertext_sha256,
            event_timestamp=event_ts_str,
            protocol_version=CanonicalizationService.PROTOCOL_VERSION,
        )

        # Step 2: Compute SHA-256 hash of canonical record
        canonical_hash = ProvenanceHashService.hash_canonical_record(canonical_bytes)

        # Step 3: Sign using active ML-DSA-65 key
        active_key = cls.ensure_active_signing_key(db)
        sig_b64, key_id, key_version = ProvenanceSigningService.sign_canonical_record(
            db=db,
            canonical_bytes=canonical_bytes,
            signing_key=active_key,
        )

        # Step 4: Atomic Chain Sequencing & Hash Chaining (Thread-safe concurrency control)
        with cls._chain_lock:
            head = cls.ensure_genesis(db, chain_id)
            new_sequence = head.latest_sequence + 1
            previous_record_hash = head.latest_chain_hash

            chain_hash = ProvenanceChainService.calculate_chain_hash(
                chain_id=chain_id,
                chain_sequence=new_sequence,
                previous_record_hash=previous_record_hash,
                canonical_record_hash=canonical_hash,
                event_id=event_id,
            )

            # Persist ProvenanceRecord
            record = ProvenanceRecord(
                id=str(uuid.uuid4()),
                event_id=event_id,
                document_id=document_id,
                document_version_id=document_version_id,
                user_id=user_id,
                recipient_key_id=recipient_key_id,
                recipient_key_version=recipient_key_version,
                device_id=device_id,
                decryption_session_id=decryption_session_id,
                policy_id=policy_id,
                policy_version=policy_version,
                access_type=access_type,
                approval_request_id=approval_request_id,
                emergency_access_request_id=emergency_access_request_id,
                document_plaintext_sha256=document_plaintext_sha256.lower(),
                document_ciphertext_sha256=document_ciphertext_sha256.lower(),
                event_timestamp=event_ts_str,
                protocol_version=CanonicalizationService.PROTOCOL_VERSION,
                provenance_version=1,
                canonical_record_hash=canonical_hash,
                signature_algorithm=ProvenanceSigningService.ALGORITHM,
                signature_key_id=key_id,
                signature_key_version=key_version,
                signature=sig_b64,
                chain_id=chain_id,
                chain_sequence=new_sequence,
                previous_record_hash=previous_record_hash,
                chain_hash=chain_hash,
                chain_version=1,
                ledger_status="PENDING",
                created_at=now,
            )
            db.add(record)
            db.flush()

            # Enqueue into Transactional Outbox
            ledger_payload = {
                "chain_id": chain_id,
                "chain_sequence": new_sequence,
                "chain_hash": chain_hash,
                "event_id": event_id,
                "document_id": document_id,
                "document_version_id": document_version_id,
                "canonical_record_hash": canonical_hash,
                "previous_record_hash": previous_record_hash,
                "signature_algorithm": record.signature_algorithm,
                "signature_key_version": key_version,
                "signature": sig_b64,
                "event_timestamp": event_ts_str,
            }
            outbox = LedgerService.enqueue_outbox(
                db=db,
                event_id=event_id,
                chain_id=chain_id,
                chain_sequence=new_sequence,
                chain_hash=chain_hash,
                payload_data=ledger_payload,
            )

            # Step 5: Attempt Immediate Ledger Anchoring
            try:
                tx_res = LedgerService.anchor_record(ledger_payload)
                record.ledger_transaction_id = tx_res.transaction_id
                record.ledger_status = "CONFIRMED"
                record.ledger_record_hash = tx_res.chain_hash
                record.ledger_anchored_at = datetime.now(timezone.utc)
                outbox.status = "CONFIRMED"
            except Exception as ledger_err:
                logger.warning("Immediate ledger anchoring deferred to outbox worker: %s", ledger_err)
                record.ledger_status = "SIGNED_BUT_NOT_ANCHORED"
                outbox.status = "PENDING"

            # Step 6: Update Chain Head Tip
            head.latest_sequence = new_sequence
            head.latest_chain_hash = chain_hash
            head.updated_at = now

            db.commit()
            db.refresh(record)

        # Step 7: Audit Event
        AuditService.log_event(
            db=db,
            event_type="PROVENANCE_CREATED",
            user_id=user_id,
            document_id=document_id,
            session_id=decryption_session_id,
            metadata={
                "event_id": event_id,
                "document_version_id": document_version_id,
                "policy_version": policy_version,
                "access_type": access_type,
                "signature_algorithm": record.signature_algorithm,
                "signature_key_version": key_version,
                "canonical_record_hash": canonical_hash,
                "chain_sequence": new_sequence,
                "chain_hash": chain_hash,
                "ledger_status": record.ledger_status,
                "ledger_transaction_id": record.ledger_transaction_id,
            },
        )

        return record

    @classmethod
    def get_chain_head(cls, db: Session, chain_id: str = DEFAULT_CHAIN_ID, requesting_user: Optional[User] = None) -> ProvenanceChainHead:
        """Retrieves the verifiable tip of the provenance hash chain."""
        with cls._chain_lock:
            head = cls.ensure_genesis(db, chain_id)
            return head

    @classmethod
    def list_chain_records(
        cls, db: Session, chain_id: str = DEFAULT_CHAIN_ID, requesting_user: Optional[User] = None, skip: int = 0, limit: int = 50
    ) -> List[ProvenanceRecord]:
        """Lists records from the provenance chain in sequence order with pagination."""
        if requesting_user and requesting_user.role not in [UserRole.ADMIN.value, UserRole.OFFICER.value, UserRole.AUDITOR.value]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized to inspect chain records.")

        return (
            db.query(ProvenanceRecord)
            .filter(ProvenanceRecord.chain_id == chain_id)
            .order_by(ProvenanceRecord.chain_sequence.asc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    @classmethod
    def verify_chain(
        cls, db: Session, chain_id: str = DEFAULT_CHAIN_ID, verifying_user: Optional[User] = None
    ) -> ProvenanceChainVerificationResponse:
        """Performs full end-to-end audit verification of the provenance hash chain."""
        if verifying_user and verifying_user.role not in [UserRole.ADMIN.value, UserRole.OFFICER.value, UserRole.AUDITOR.value]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized to execute chain verification.")

        records = (
            db.query(ProvenanceRecord)
            .filter(ProvenanceRecord.chain_id == chain_id)
            .order_by(ProvenanceRecord.chain_sequence.asc())
            .all()
        )

        now_str = CanonicalizationService.normalize_timestamp(datetime.now(timezone.utc))

        if not records:
            return ProvenanceChainVerificationResponse(
                chain_valid=True,
                chain_id=chain_id,
                records_checked=0,
                first_invalid_sequence=None,
                failure_type=None,
                failure_detail="Chain is empty.",
                signatures_verified=0,
                ledger_anchors_verified=0,
                verified_at=now_str,
            )

        # 1. Verify Genesis at sequence 0
        genesis = records[0]
        if genesis.chain_sequence != 0 or genesis.previous_record_hash != ("0" * 64):
            return ProvenanceChainVerificationResponse(
                chain_valid=False,
                chain_id=chain_id,
                records_checked=1,
                first_invalid_sequence=genesis.chain_sequence,
                failure_type="GENESIS_CORRUPTED",
                failure_detail=f"Genesis record at sequence {genesis.chain_sequence} has invalid previous hash.",
                signatures_verified=0,
                ledger_anchors_verified=0,
                verified_at=now_str,
            )

        expected_genesis_hash = ProvenanceChainService.calculate_chain_hash(
            chain_id=chain_id,
            chain_sequence=0,
            previous_record_hash="0" * 64,
            canonical_record_hash=genesis.canonical_record_hash,
            event_id=genesis.event_id,
        )
        if genesis.chain_hash != expected_genesis_hash:
            return ProvenanceChainVerificationResponse(
                chain_valid=False,
                chain_id=chain_id,
                records_checked=1,
                first_invalid_sequence=0,
                failure_type="CHAIN_HASH_MISMATCH",
                failure_detail="Genesis chain hash mismatch.",
                signatures_verified=0,
                ledger_anchors_verified=0,
                verified_at=now_str,
            )

        signatures_verified = 0
        ledger_anchors_verified = 1 if genesis.ledger_status == "CONFIRMED" else 0

        # 2. Iterate through subsequent chain records
        for i in range(1, len(records)):
            prev_rec = records[i - 1]
            rec = records[i]

            # Sequence continuity check
            if rec.chain_sequence != prev_rec.chain_sequence + 1:
                return ProvenanceChainVerificationResponse(
                    chain_valid=False,
                    chain_id=chain_id,
                    records_checked=i + 1,
                    first_invalid_sequence=rec.chain_sequence,
                    failure_type="SEQUENCE_GAP",
                    failure_detail=f"Sequence gap detected: expected {prev_rec.chain_sequence + 1}, found {rec.chain_sequence}.",
                    signatures_verified=signatures_verified,
                    ledger_anchors_verified=ledger_anchors_verified,
                    verified_at=now_str,
                )

            # Previous hash linkage check
            if rec.previous_record_hash != prev_rec.chain_hash:
                return ProvenanceChainVerificationResponse(
                    chain_valid=False,
                    chain_id=chain_id,
                    records_checked=i + 1,
                    first_invalid_sequence=rec.chain_sequence,
                    failure_type="PREVIOUS_HASH_MISMATCH",
                    failure_detail=f"Previous hash mismatch at sequence {rec.chain_sequence}.",
                    signatures_verified=signatures_verified,
                    ledger_anchors_verified=ledger_anchors_verified,
                    verified_at=now_str,
                )

            # Recompute chain hash
            computed_chain_hash = ProvenanceChainService.calculate_chain_hash(
                chain_id=chain_id,
                chain_sequence=rec.chain_sequence,
                previous_record_hash=rec.previous_record_hash,
                canonical_record_hash=rec.canonical_record_hash,
                event_id=rec.event_id,
            )
            if rec.chain_hash != computed_chain_hash:
                return ProvenanceChainVerificationResponse(
                    chain_valid=False,
                    chain_id=chain_id,
                    records_checked=i + 1,
                    first_invalid_sequence=rec.chain_sequence,
                    failure_type="CHAIN_HASH_MISMATCH",
                    failure_detail=f"Computed chain hash {computed_chain_hash} does not match stored {rec.chain_hash}.",
                    signatures_verified=signatures_verified,
                    ledger_anchors_verified=ledger_anchors_verified,
                    verified_at=now_str,
                )

            # Verify ML-DSA-65 digital signature
            sig_result = ProvenanceVerificationService.verify_record(db, rec)
            if not sig_result["verified"]:
                return ProvenanceChainVerificationResponse(
                    chain_valid=False,
                    chain_id=chain_id,
                    records_checked=i + 1,
                    first_invalid_sequence=rec.chain_sequence,
                    failure_type="SIGNATURE_INVALID",
                    failure_detail=f"Signature verification failed: {sig_result.get('reason')}",
                    signatures_verified=signatures_verified,
                    ledger_anchors_verified=ledger_anchors_verified,
                    verified_at=now_str,
                )
            signatures_verified += 1

            # Verify Ledger Anchor if confirmed
            if rec.ledger_status == "CONFIRMED" and rec.ledger_transaction_id:
                anchor_res = LedgerService.verify_anchor(rec.ledger_transaction_id, rec.chain_hash)
                if not anchor_res.hash_matched:
                    return ProvenanceChainVerificationResponse(
                        chain_valid=False,
                        chain_id=chain_id,
                        records_checked=i + 1,
                        first_invalid_sequence=rec.chain_sequence,
                        failure_type="LEDGER_ANCHOR_MISMATCH",
                        failure_detail=f"Ledger anchor mismatch at sequence {rec.chain_sequence}: {anchor_res.details}",
                        signatures_verified=signatures_verified,
                        ledger_anchors_verified=ledger_anchors_verified,
                        verified_at=now_str,
                    )
                ledger_anchors_verified += 1

        # Audit event for chain verification
        if verifying_user:
            AuditService.log_event(
                db=db,
                event_type="PROVENANCE_CHAIN_VERIFIED",
                user_id=verifying_user.id,
                metadata={
                    "chain_id": chain_id,
                    "records_checked": len(records),
                    "signatures_verified": signatures_verified,
                    "ledger_anchors_verified": ledger_anchors_verified,
                },
            )

        return ProvenanceChainVerificationResponse(
            chain_valid=True,
            chain_id=chain_id,
            records_checked=len(records),
            first_invalid_sequence=None,
            failure_type=None,
            failure_detail=None,
            signatures_verified=signatures_verified,
            ledger_anchors_verified=ledger_anchors_verified,
            verified_at=now_str,
        )

    @classmethod
    def verify_ledger_anchor(
        cls, db: Session, event_id: str, verifying_user: Optional[User] = None
    ) -> LedgerAnchorVerificationResponse:
        """Verifies a single record's anchor against the configured ledger adapter."""
        rec = db.query(ProvenanceRecord).filter(ProvenanceRecord.event_id == event_id).first()
        if not rec:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provenance record not found.")

        if not rec.ledger_transaction_id:
            return LedgerAnchorVerificationResponse(
                event_id=event_id,
                is_anchored=False,
                transaction_id=None,
                expected_chain_hash=rec.chain_hash,
                ledger_chain_hash=None,
                hash_matched=False,
                status="NOT_ANCHORED",
                details="Record has not been anchored to the ledger yet (status: SIGNED_BUT_NOT_ANCHORED).",
            )

        res = LedgerService.verify_anchor(rec.ledger_transaction_id, rec.chain_hash)
        return LedgerAnchorVerificationResponse(
            event_id=event_id,
            is_anchored=res.is_anchored,
            transaction_id=res.transaction_id,
            expected_chain_hash=res.expected_chain_hash,
            ledger_chain_hash=res.ledger_chain_hash,
            hash_matched=res.hash_matched,
            status=res.status,
            details=res.details,
            anchored_at=res.anchored_at,
        )

    @classmethod
    def get_provenance_for_document(
        cls, db: Session, document_id: str, requesting_user: User
    ) -> List[ProvenanceRecord]:
        """Returns provenance history for a document. Enforces authorization."""
        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found.")

        is_privileged = requesting_user.role in [
            UserRole.ADMIN.value,
            UserRole.OFFICER.value,
            UserRole.AUDITOR.value,
        ]
        is_owner = (doc.owner_id == requesting_user.id)

        query = db.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == document_id)

        if not (is_privileged or is_owner):
            query = query.filter(ProvenanceRecord.user_id == requesting_user.id)

        return query.order_by(ProvenanceRecord.chain_sequence.desc()).all()

    @classmethod
    def get_provenance_by_event_id(
        cls, db: Session, event_id: str, requesting_user: User
    ) -> ProvenanceRecord:
        """Retrieves a single provenance record by its event ID with authorization checks."""
        record = db.query(ProvenanceRecord).filter(ProvenanceRecord.event_id == event_id).first()
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provenance record not found.")

        is_privileged = requesting_user.role in [
            UserRole.ADMIN.value,
            UserRole.OFFICER.value,
            UserRole.AUDITOR.value,
        ]
        if not is_privileged and record.user_id != requesting_user.id:
            doc = db.query(Document).filter(Document.id == record.document_id).first()
            if not doc or doc.owner_id != requesting_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Unauthorized to inspect this provenance record.",
                )

        return record

    @classmethod
    def verify_provenance(
        cls, db: Session, event_id: str, verifying_user: User
    ) -> ProvenanceVerificationResponse:
        """Cryptographically verifies a provenance record and emits audit evidence."""
        record = cls.get_provenance_by_event_id(db, event_id, verifying_user)
        result = ProvenanceVerificationService.verify_record(db, record)

        now_str = CanonicalizationService.normalize_timestamp(datetime.now(timezone.utc))

        audit_event_type = "PROVENANCE_VERIFIED" if result["verified"] else "PROVENANCE_VERIFICATION_FAILED"
        AuditService.log_event(
            db=db,
            event_type=audit_event_type,
            user_id=verifying_user.id,
            document_id=record.document_id,
            session_id=record.decryption_session_id,
            metadata={
                "event_id": event_id,
                "verified": result["verified"],
                "hash_valid": result["hash_valid"],
                "signature_valid": result["signature_valid"],
                "signing_key_version": result["signing_key_version"],
                "reason": result.get("reason"),
            },
        )

        return ProvenanceVerificationResponse(
            event_id=result["event_id"],
            hash_valid=result["hash_valid"],
            signature_valid=result["signature_valid"],
            signing_key_version=result["signing_key_version"],
            verified=result["verified"],
            reason=result.get("reason"),
            verified_at=now_str,
        )

    @classmethod
    def process_ledger_outbox(cls, db: Session, admin_user: User, max_items: int = 50) -> LedgerOutboxProcessResponse:
        """Manually or asynchronously triggers outbox processing."""
        if admin_user.role != UserRole.ADMIN.value:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only administrators can process ledger outbox.")
        res = LedgerService.process_outbox(db=db, max_items=max_items)
        return LedgerOutboxProcessResponse(**res)
