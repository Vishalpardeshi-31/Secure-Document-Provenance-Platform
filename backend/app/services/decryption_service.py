import base64
import logging
import threading
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session

from app.models.document import Document
from app.models.document_recipient import DocumentRecipient
from app.models.recipient_key import RecipientKey
from app.models.decryption_session import DecryptionSession
from app.models.user import User
from app.security.crypto_service import CryptoService
from app.security.key_management_service import KeyManagementService
from app.security.recipient_key_manager import RecipientKeyManager
from app.services.document_storage_service import DocumentStorageService
from app.services.policy_evaluation_service import PolicyEvaluationService, PolicyDecision
from app.services.audit_service import AuditService
from app.provenance.service import ProvenanceService

logger = logging.getLogger("secure_document_platform.decryption_service")


class DecryptionService:
    """Orchestrates the complete policy-controlled decryption workflow.
    
    Guarantees:
    - Pre-decryption policy evaluation (identity, active key, role, time window, device, max limit).
    - Recipient-specific key recovery (ML-KEM-768 decapsulation + HKDF + AES-GCM unwrap).
    - Ciphertext integrity validation (SHA-256).
    - AES-256-GCM authentication verification (detects any tampering with ciphertext/tag/nonce/AAD).
    - Plaintext integrity validation (SHA-256).
    - Concurrency and race-condition protection for single-use / N-use documents.
    - Zero plaintext written to public or permanent disk storage.
    - Comprehensive cryptographic audit trail with session lifecycle states.
    """

    _concurrency_lock = threading.RLock()

    @classmethod
    def request_and_decrypt(
        cls,
        db: Session,
        document_id: str,
        user: User,
        device_id: Optional[str] = None,
        request_context: Optional[Dict[str, Any]] = None,
        approval_request_id: Optional[str] = None,
        emergency_request_id: Optional[str] = None,
    ) -> Tuple[DecryptionSession, bytes]:
        """Atomically evaluates authorization and policy, recovers DEK, and decrypts document.
        
        Returns:
            Tuple of (DecryptionSession, plaintext_bytes).
            
        Raises:
            PermissionError: If policy or recipient authorization denies access.
            ValueError: If integrity verification or cryptographic authentication fails.
        """
        if emergency_request_id:
            from app.services.emergency_service import EmergencyAccessService
            return EmergencyAccessService.execute_emergency_decryption(
                db=db,
                document_id=document_id,
                user=user,
                emergency_request_id=emergency_request_id,
                device_id=device_id,
            )

        with cls._concurrency_lock:
            now = datetime.now(timezone.utc)

            doc = db.query(Document).filter(Document.id == document_id).first()
            if not doc:
                raise ValueError("Document not found.")

            recipient = (
                db.query(DocumentRecipient)
                .filter(
                    DocumentRecipient.document_id == doc.id,
                    DocumentRecipient.user_id == user.id,
                )
                .first()
            )

            # Step 1: Create initial DecryptionSession
            session_id = str(uuid.uuid4())
            version_id = doc.versions[0].id if doc.versions else str(uuid.uuid4())
            session_token_hash = CryptoService.calculate_sha256(uuid.uuid4().bytes)

            session = DecryptionSession(
                id=session_id,
                document_id=doc.id,
                version_id=version_id,
                user_id=user.id,
                device_id=device_id,
                session_token_hash=session_token_hash,
                status="REQUESTED",
                started_at=now,
                expires_at=now + timedelta(minutes=15),
            )
            AuditService.log_event(
                db=db,
                event_type="DOCUMENT_DECRYPTION_REQUESTED",
                user_id=user.id,
                document_id=doc.id,
                session_id=session.id,
                metadata={
                    "document_id": doc.id,
                    "device_id": device_id,
                    "original_filename": doc.original_filename,
                },
            )

            # Step 2: Policy Evaluation using authoritative policy engine
            from app.policies import default_evaluator, PolicyService, PolicyReasonCode

            active_policy = PolicyService.get_active_policy(db, doc.id)

            eval_context = dict(request_context or {})
            if approval_request_id:
                eval_context["approval_request_id"] = approval_request_id
            eval_context["session_id"] = session.id

            decision = default_evaluator.evaluate(
                db=db,
                user=user,
                document=doc,
                recipient=recipient,
                policy=active_policy,
                device_id=device_id,
                current_time=now,
                context=eval_context,
            )


            if not decision.allowed:
                session.status = "DENIED"
                session.failure_reason_code = decision.reason_code
                session.ended_at = datetime.now(timezone.utc)
                if decision.policy_id:
                    session.policy_id = decision.policy_id
                if decision.policy_version:
                    session.policy_version = decision.policy_version
                db.add(session)
                db.commit()

                # Specific audit events based on failure category
                if decision.reason_code in [
                    PolicyReasonCode.DEVICE_REQUIRED.value,
                    PolicyReasonCode.DEVICE_NOT_REGISTERED.value,
                    PolicyReasonCode.DEVICE_NOT_AUTHORIZED.value,
                    PolicyReasonCode.DEVICE_REVOKED.value,
                ]:
                    AuditService.log_event(
                        db=db,
                        event_type="DEVICE_CHECK_FAILED",
                        user_id=user.id,
                        document_id=doc.id,
                        session_id=session.id,
                        metadata={
                            "reason_code": decision.reason_code,
                            "device_id": device_id,
                            "message": decision.message,
                        },
                    )
                elif decision.reason_code in [
                    PolicyReasonCode.POLICY_NOT_ACTIVE.value,
                    PolicyReasonCode.POLICY_NOT_YET_ACTIVE.value,
                    PolicyReasonCode.POLICY_EXPIRED.value,
                    PolicyReasonCode.DECRYPTION_LIMIT_REACHED.value,
                    PolicyReasonCode.POLICY_REQUIRES_APPROVAL.value,
                    PolicyReasonCode.POLICY_DENIED.value,
                    PolicyReasonCode.ROLE_NOT_AUTHORIZED.value,
                    "ACCESS_NOT_YET_VALID",
                    "ACCESS_EXPIRED",
                    "MAX_DECRYPTIONS_REACHED",
                ]:
                    AuditService.log_event(
                        db=db,
                        event_type="POLICY_CHECK_FAILED",
                        user_id=user.id,
                        document_id=doc.id,
                        session_id=session.id,
                        metadata={
                            "reason_code": decision.reason_code,
                            "policy_id": decision.policy_id,
                            "policy_version": decision.policy_version,
                            "message": decision.message,
                        },
                    )

                AuditService.log_event(
                    db=db,
                    event_type="DECRYPTION_AUTHORIZATION_DENIED",
                    user_id=user.id,
                    document_id=doc.id,
                    session_id=session.id,
                    metadata={
                        "reason_code": decision.reason_code,
                        "policy_id": decision.policy_id,
                        "policy_version": decision.policy_version,
                        "message": decision.message,
                    },
                )
                legacy_reason = (
                    "NOT_DOCUMENT_RECIPIENT"
                    if decision.reason_code == PolicyReasonCode.RECIPIENT_NOT_AUTHORIZED.value
                    else decision.reason_code
                )
                AuditService.log_event(
                    db=db,
                    event_type="DOCUMENT_DECRYPTION_DENIED",
                    user_id=user.id,
                    document_id=doc.id,
                    session_id=session.id,
                    metadata={
                        "reason_code": legacy_reason,
                        "policy_reason_code": decision.reason_code,
                        "message": decision.message,
                    },
                )
                raise PermissionError(decision.message or "Decryption access denied by policy.")

            # Step 3: Authorization passed -> Atomically reserve/consume decryption count
            session.status = "AUTHORIZED"
            session.authorized_at = datetime.now(timezone.utc)
            if decision.policy_id:
                session.policy_id = decision.policy_id
            if decision.policy_version:
                session.policy_version = decision.policy_version

            if approval_request_id:
                from app.models.approval import ApprovalRequest
                app_req = db.query(ApprovalRequest).filter(ApprovalRequest.id == approval_request_id).first()
                if app_req:
                    app_req.decryption_session_id = session.id

            db.add(session)
            db.commit()


            # Concurrency-safe atomic reservation/consumption
            PolicyService.reserve_and_consume_decryption(
                db=db,
                policy_id=decision.policy_id,
                user_id=user.id,
                document_id=doc.id,
            )
            db.commit()

            AuditService.log_event(
                db=db,
                event_type="DECRYPTION_AUTHORIZATION_GRANTED",
                user_id=user.id,
                document_id=doc.id,
                session_id=session.id,
                metadata={
                    "document_id": doc.id,
                    "policy_id": decision.policy_id,
                    "policy_version": decision.policy_version,
                },
            )
            AuditService.log_event(
                db=db,
                event_type="DOCUMENT_DECRYPTION_AUTHORIZED",
                user_id=user.id,
                document_id=doc.id,
                session_id=session.id,
                metadata={"document_id": doc.id},
            )

            # Step 4: Cryptographic Decryption Workflow
            session.status = "DECRYPTING"
            db.commit()

            try:
                # 4a. Retrieve recipient key record matching recipient key version
                key_record = (
                    db.query(RecipientKey)
                    .filter(
                        RecipientKey.user_id == user.id,
                        RecipientKey.key_version == recipient.recipient_key_version,
                    )
                    .first()
                )
                if not key_record:
                    raise ValueError(f"Recipient key version {recipient.recipient_key_version} not found in database.")

                # 4b. Recover recipient private key
                recipient_priv = RecipientKeyManager._unwrap_private_key(key_record)

                from app.crypto.aad import build_document_aad

                if doc.key_management_version == 1:
                    # Legacy Phase 3 path: unwrap server KEK envelope
                    recovered_dek = KeyManagementService.unwrap_dek(doc.encrypted_dek)
                    aad = f"SDPP-DOC:{doc.id}".encode("utf-8")
                elif doc.key_management_version == 2:
                    if not recipient:
                        raise PermissionError("User is not an authorized recipient for this document.")
                    # Modern recipient-wrapped path: ML-KEM decapsulation + HKDF + AES-GCM unwrap
                    recovered_dek = KeyManagementService.unwrap_dek_for_recipient(
                        encapsulated_key_b64=recipient.encapsulated_key or recipient.kem_ciphertext,
                        nonce_b64=recipient.wrap_nonce or recipient.nonce,
                        wrapped_dek_b64=recipient.wrapped_dek,
                        recipient_priv=recipient_priv,
                        document_id=doc.id,
                        document_version_id="1",
                        recipient_user_id=user.id,
                        recipient_key_id=recipient.recipient_key_id or (key_record.id if key_record else None),
                        recipient_key_version=recipient.recipient_key_version,
                        protocol_version=doc.protocol_version,
                    )
                    aad = build_document_aad(
                        document_id=doc.id,
                        document_version_id="1",
                        protocol_version=doc.protocol_version,
                    )
                else:
                    raise ValueError(f"Unsupported key management version: {doc.key_management_version}")

                # 4d. Read ciphertext from protected storage
                ciphertext = DocumentStorageService.read_encrypted_bytes(doc.storage_reference)

                # 4e. Verify ciphertext integrity
                calculated_c_sha = CryptoService.calculate_sha256(ciphertext)
                if calculated_c_sha != doc.ciphertext_sha256:
                    AuditService.log_event(
                        db=db,
                        event_type="INTEGRITY_CHECK_FAILED",
                        user_id=user.id,
                        document_id=doc.id,
                        session_id=session.id,
                        metadata={
                            "check_target": "ciphertext",
                            "expected_sha256": doc.ciphertext_sha256,
                            "calculated_sha256": calculated_c_sha,
                        },
                    )
                    raise ValueError("Ciphertext integrity verification failed (SHA-256 mismatch).")

                # 4f. Authenticate and decrypt AES-256-GCM
                doc_nonce = base64.b64decode(doc.nonce)
                plaintext = CryptoService.decrypt_bytes(
                    key=recovered_dek,
                    nonce=doc_nonce,
                    ciphertext_and_tag=ciphertext,
                    associated_data=aad,
                )

                # 4g. Verify plaintext integrity
                calculated_p_sha = CryptoService.calculate_sha256(plaintext)
                if calculated_p_sha != doc.plaintext_sha256:
                    AuditService.log_event(
                        db=db,
                        event_type="INTEGRITY_CHECK_FAILED",
                        user_id=user.id,
                        document_id=doc.id,
                        session_id=session.id,
                        metadata={
                            "check_target": "plaintext",
                            "expected_sha256": doc.plaintext_sha256,
                            "calculated_sha256": calculated_p_sha,
                        },
                    )
                    raise ValueError("Plaintext integrity verification failed (SHA-256 mismatch).")

                # Step 5: Record Cryptographic Provenance (Phase 9)
                access_type = "MULTI_PARTY_APPROVED" if approval_request_id else "NORMAL"
                policy_id = decision.policy_id or (session.policy_id or "DEFAULT")
                policy_version = decision.policy_version if decision.policy_version is not None else (session.policy_version or 1)
                doc_version_id = session.version_id or str(getattr(doc, "current_version", "1"))
                rec_key_id = recipient.recipient_key_id if (recipient and recipient.recipient_key_id) else (key_record.id if key_record else None)
                rec_key_ver = recipient.recipient_key_version if recipient else (key_record.key_version if key_record else None)

                provenance_rec = ProvenanceService.record_decryption_provenance(
                    db=db,
                    document_id=doc.id,
                    document_version_id=doc_version_id,
                    user_id=user.id,
                    recipient_key_id=rec_key_id,
                    recipient_key_version=rec_key_ver,
                    device_id=device_id,
                    decryption_session_id=session.id,
                    policy_id=policy_id,
                    policy_version=policy_version,
                    access_type=access_type,
                    approval_request_id=approval_request_id,
                    emergency_access_request_id=None,
                    document_plaintext_sha256=doc.plaintext_sha256,
                    document_ciphertext_sha256=doc.ciphertext_sha256,
                )

                # Step 6: Mark Completed
                session.status = "COMPLETED"
                session.completed_at = datetime.now(timezone.utc)
                session.ended_at = datetime.now(timezone.utc)
                db.commit()

                AuditService.log_event(
                    db=db,
                    event_type="DOCUMENT_DECRYPTION_COMPLETED",
                    user_id=user.id,
                    document_id=doc.id,
                    session_id=session.id,
                    metadata={
                        "original_filename": doc.original_filename,
                        "plaintext_sha256": doc.plaintext_sha256,
                        "ciphertext_sha256": doc.ciphertext_sha256,
                        "decrypted_size_bytes": len(plaintext),
                    },
                )

                return session, plaintext

            except Exception as crypto_err:
                logger.error(f"Decryption execution failed for session {session.id}: {crypto_err}", exc_info=True)
                session.status = "FAILED"
                session.failure_reason_code = type(crypto_err).__name__
                session.ended_at = datetime.now(timezone.utc)
                try:
                    db.commit()
                except Exception:
                    db.rollback()

                AuditService.log_event(
                    db=db,
                    event_type="DOCUMENT_DECRYPTION_FAILED",
                    user_id=user.id,
                    document_id=doc.id,
                    session_id=session.id,
                    metadata={
                        "error_type": type(crypto_err).__name__,
                        "error_detail": str(crypto_err),
                    },
                )
                raise
