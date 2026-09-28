"""Emergency Break-Glass Access Service with mandatory independent authorization and audit trail."""
import base64
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session

from app.models.emergency_access import EmergencyAccessRequest
from app.models.document import Document
from app.models.document_recipient import DocumentRecipient
from app.models.recipient_key import RecipientKey
from app.models.decryption_session import DecryptionSession
from app.models.access_policy import AccessPolicy
from app.models.user import User
from app.models.role import UserRole
from app.security.crypto_service import CryptoService
from app.security.key_management_service import KeyManagementService
from app.security.recipient_key_manager import RecipientKeyManager
from app.services.document_storage_service import DocumentStorageService
from app.policies.service import PolicyService as EnginePolicyService
from app.policies.models import DocumentLifecycleStatus
from app.services.audit_service import AuditService
from app.provenance.service import ProvenanceService

logger = logging.getLogger("secure_document_platform.emergency_service")


class EmergencyAccessService:
    """Manages emergency break-glass requests, independent authorizations, and controlled decryption."""

    MIN_REASON_LENGTH = 15
    DEFAULT_DURATION_MINUTES = 15
    MAX_DURATION_MINUTES = 60

    @staticmethod
    def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @classmethod
    def request_emergency_access(

        cls,
        db: Session,
        document_id: str,
        user: User,
        reason: str,
        requested_duration_minutes: Optional[int] = None,
    ) -> EmergencyAccessRequest:
        """Initiates an emergency break-glass access request."""
        now = datetime.now(timezone.utc)

        # 1. User check
        if not user.is_active:
            raise PermissionError("Requesting user account is inactive or disabled.")

        # Explicit EMERGENCY_DECRYPT permission check (separate from ordinary ADMIN role)
        has_perm = bool(getattr(user, "can_emergency_decrypt", False))
        if not has_perm:
            raise PermissionError("User does not possess the explicit EMERGENCY_DECRYPT permission.")

        # 2. Reason validation
        clean_reason = (reason or "").strip()
        if len(clean_reason) < cls.MIN_REASON_LENGTH:
            raise ValueError(
                f"Emergency access requires an explicit incident response reason (minimum {cls.MIN_REASON_LENGTH} characters)."
            )

        # 3. Document validation
        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            raise ValueError("Document not found.")

        if (doc.status or "").upper() == DocumentLifecycleStatus.REVOKED.value:
            raise PermissionError("Document has been administratively revoked.")

        # 4. Policy validation
        policy = EnginePolicyService.get_active_policy(db, doc.id)
        if not policy:
            raise ValueError("No active access policy found for this document.")

        if not getattr(policy, "allow_emergency_access", False):
            raise PermissionError("Emergency break-glass access is not permitted by this document's access policy.")

        if policy.eligible_emergency_roles:
            eligible_roles = [r.strip().upper() for r in policy.eligible_emergency_roles.split(",") if r.strip()]
            if eligible_roles and user.role.upper() not in eligible_roles:
                raise PermissionError(f"User role '{user.role}' is not eligible for emergency access.")

        # 5. Duration constraint: server-enforced upper bound
        max_dur = policy.maximum_emergency_duration or cls.DEFAULT_DURATION_MINUTES
        duration = min(requested_duration_minutes or max_dur, max_dur)
        if duration < 1:
            duration = cls.DEFAULT_DURATION_MINUTES

        expires_at = now + timedelta(minutes=duration)

        request = EmergencyAccessRequest(
            document_id=doc.id,
            requester_user_id=user.id,
            requester_role=user.role,
            reason=clean_reason,
            status="REQUESTED",
            created_at=now,
            expires_at=expires_at,
        )
        db.add(request)
        db.commit()
        db.refresh(request)

        AuditService.log_event(
            db=db,
            event_type="EMERGENCY_ACCESS_REQUESTED",
            user_id=user.id,
            document_id=doc.id,
            metadata={
                "emergency_request_id": request.id,
                "reason": clean_reason,
                "duration_minutes": duration,
                "expires_at": expires_at.isoformat(),
            },
        )
        return request

    @classmethod
    def approve_emergency_access(
        cls,
        db: Session,
        request_id: str,
        approver: User,
        reason: Optional[str] = None,
    ) -> EmergencyAccessRequest:
        """Independently authorizes an emergency break-glass access request."""
        now = datetime.now(timezone.utc)

        request = db.query(EmergencyAccessRequest).filter(EmergencyAccessRequest.id == request_id).first()
        if not request:
            raise ValueError("Emergency access request not found.")

        # Lazy expiration check
        if request.status == "REQUESTED" and now > cls._to_utc(request.expires_at):
            request.status = "EXPIRED"
            db.commit()
            AuditService.log_event(
                db=db,
                event_type="EMERGENCY_ACCESS_EXPIRED",
                user_id=request.requester_user_id,
                document_id=request.document_id,
                metadata={"emergency_request_id": request.id},
            )
            raise ValueError("Emergency access request has expired and cannot be authorized.")


        if request.status != "REQUESTED":
            raise ValueError(f"Emergency request cannot be authorized (current status: {request.status}).")

        # APPROVER INDEPENDENCE: Requester cannot approve their own emergency request
        if approver.id == request.requester_user_id:
            raise PermissionError("Requester cannot authorize their own emergency access request.")

        if not approver.is_active:
            raise PermissionError("Approver user account is inactive or disabled.")

        if approver.role not in [UserRole.ADMIN.value, UserRole.OFFICER.value]:
            raise PermissionError("Approver does not possess emergency authorization privileges.")

        policy = EnginePolicyService.get_active_policy(db, request.document_id)
        max_dur = policy.maximum_emergency_duration if policy else cls.DEFAULT_DURATION_MINUTES
        auth_expires_at = now + timedelta(minutes=max_dur)

        request.status = "AUTHORIZED"
        request.approved_at = now
        request.expires_at = auth_expires_at
        request.approver_user_id = approver.id

        db.commit()
        db.refresh(request)

        AuditService.log_event(
            db=db,
            event_type="EMERGENCY_ACCESS_APPROVED",
            user_id=approver.id,
            document_id=request.document_id,
            metadata={
                "emergency_request_id": request.id,
                "requester_id": request.requester_user_id,
                "approver_id": approver.id,
                "approved_at": now.isoformat(),
                "expires_at": auth_expires_at.isoformat(),
                "reason": reason,
            },
        )
        return request

    @classmethod
    def reject_emergency_access(
        cls,
        db: Session,
        request_id: str,
        approver: User,
        reason: str,
    ) -> EmergencyAccessRequest:
        """Rejects an emergency access request."""
        now = datetime.now(timezone.utc)

        clean_reason = (reason or "").strip()
        if not clean_reason:
            raise ValueError("A rejection reason is required.")

        request = db.query(EmergencyAccessRequest).filter(EmergencyAccessRequest.id == request_id).first()
        if not request:
            raise ValueError("Emergency access request not found.")

        if approver.id == request.requester_user_id:
            raise PermissionError("Requester cannot decide on their own emergency request.")

        if not approver.is_active:
            raise PermissionError("Approver user account is inactive or disabled.")

        if approver.role not in [UserRole.ADMIN.value, UserRole.OFFICER.value]:
            raise PermissionError("Approver does not possess authorization privileges.")

        if request.status != "REQUESTED":
            raise ValueError(f"Emergency request cannot be rejected (current status: {request.status}).")

        request.status = "REJECTED"
        request.rejection_reason = clean_reason
        request.completed_at = now
        request.approver_user_id = approver.id

        db.commit()
        db.refresh(request)

        AuditService.log_event(
            db=db,
            event_type="EMERGENCY_ACCESS_REJECTED",
            user_id=approver.id,
            document_id=request.document_id,
            metadata={
                "emergency_request_id": request.id,
                "requester_id": request.requester_user_id,
                "approver_id": approver.id,
                "rejection_reason": clean_reason,
            },
        )
        return request

    @classmethod
    def execute_emergency_decryption(
        cls,
        db: Session,
        document_id: str,
        user: User,
        emergency_request_id: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> Tuple[DecryptionSession, bytes]:
        """Executes authorized emergency break-glass decryption.
        
        Guarantees:
        - Validates emergency request is AUTHORIZED and unexpired.
        - Re-checks document revocation status.
        - Uses legitimate cryptographic key recovery without exposing another user's private key.
        - Marks request as USED to prevent replay.
        - Full emergency audit trail.
        """
        now = datetime.now(timezone.utc)

        # 1. Fetch emergency request
        query = db.query(EmergencyAccessRequest).filter(
            EmergencyAccessRequest.document_id == document_id,
            EmergencyAccessRequest.requester_user_id == user.id,
        )
        if emergency_request_id:
            query = query.filter(EmergencyAccessRequest.id == emergency_request_id)
        else:
            query = query.filter(EmergencyAccessRequest.status == "AUTHORIZED")

        request = query.order_by(EmergencyAccessRequest.created_at.desc()).first()
        if not request:
            raise PermissionError("No emergency access request found for this document.")

        if request.status == "REJECTED":
            raise PermissionError("Emergency access request was rejected.")

        if request.status != "AUTHORIZED":
            raise PermissionError(f"Emergency access is not authorized (status: {request.status}).")

        # 2. Check expiration
        if now > cls._to_utc(request.expires_at):
            request.status = "EXPIRED"
            db.commit()
            AuditService.log_event(
                db=db,
                event_type="EMERGENCY_ACCESS_EXPIRED",
                user_id=user.id,
                document_id=document_id,
                metadata={"emergency_request_id": request.id},
            )
            raise PermissionError("Emergency authorization window has expired.")


        # 3. Document status check
        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            raise ValueError("Document not found.")

        if (doc.status or "").upper() == DocumentLifecycleStatus.REVOKED.value:
            raise PermissionError("Document has been administratively revoked.")

        # 4. Create emergency DecryptionSession
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
            status="AUTHORIZED",
            started_at=now,
            authorized_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        # 5. Cryptographic Key Recovery
        # If the requester is an assigned recipient with their own ML-KEM key:
        recipient = (
            db.query(DocumentRecipient)
            .filter(
                DocumentRecipient.document_id == doc.id,
                DocumentRecipient.user_id == user.id,
                DocumentRecipient.status == "ACTIVE",
            )
            .first()
        )

        from app.crypto.aad import build_document_aad

        if recipient:
            key_record = (
                db.query(RecipientKey)
                .filter(
                    RecipientKey.user_id == user.id,
                    RecipientKey.key_version == recipient.recipient_key_version,
                )
                .first()
            )
            if key_record and key_record.status != "REVOKED":
                recipient_priv = RecipientKeyManager._unwrap_private_key(key_record)
                recovered_dek = KeyManagementService.unwrap_dek_for_recipient(
                    encapsulated_key_b64=recipient.encapsulated_key or recipient.kem_ciphertext,
                    nonce_b64=recipient.wrap_nonce or recipient.nonce,
                    wrapped_dek_b64=recipient.wrapped_dek,
                    recipient_priv=recipient_priv,
                    document_id=doc.id,
                    document_version_id="1",
                    recipient_user_id=user.id,
                    recipient_key_id=recipient.recipient_key_id or key_record.id,
                    recipient_key_version=recipient.recipient_key_version,
                    protocol_version=doc.protocol_version,
                )
                aad = build_document_aad(
                    document_id=doc.id,
                    document_version_id="1",
                    protocol_version=doc.protocol_version,
                )
            else:
                # Recipient key revoked, use server KEK envelope
                recovered_dek = KeyManagementService.unwrap_dek(doc.encrypted_dek)
                aad = f"SDPP-DOC:{doc.id}".encode("utf-8") if doc.key_management_version == 1 else build_document_aad(doc.id, "1", doc.protocol_version)
        else:
            # Emergency actor is not a regular recipient:
            # Rather than touching another user's private key, the authorized server-controlled
            # KEK envelope safely releases the DEK to the authorized break-glass workflow.
            recovered_dek = KeyManagementService.unwrap_dek(doc.encrypted_dek)
            aad = f"SDPP-DOC:{doc.id}".encode("utf-8") if doc.key_management_version == 1 else build_document_aad(doc.id, "1", doc.protocol_version)

        # 6. Read ciphertext and verify integrity
        ciphertext = DocumentStorageService.read_encrypted_bytes(doc.storage_reference)
        calc_c_sha = CryptoService.calculate_sha256(ciphertext)
        if calc_c_sha != doc.ciphertext_sha256:
            raise ValueError("Ciphertext integrity verification failed.")

        # 7. Authenticate and decrypt AES-256-GCM
        doc_nonce = base64.b64decode(doc.nonce)
        plaintext = CryptoService.decrypt_bytes(
            key=recovered_dek,
            nonce=doc_nonce,
            ciphertext_and_tag=ciphertext,
            associated_data=aad,
        )

        calc_p_sha = CryptoService.calculate_sha256(plaintext)
        if calc_p_sha != doc.plaintext_sha256:
            raise ValueError("Plaintext integrity verification failed.")

        # 7b. Record Cryptographic Provenance (Phase 9 - EMERGENCY)
        rec_key_id = recipient.recipient_key_id if (recipient and getattr(recipient, "recipient_key_id", None)) else (key_record.id if (recipient and key_record) else None)
        rec_key_ver = recipient.recipient_key_version if recipient else (key_record.key_version if (recipient and key_record) else None)
        doc_version_id = session.version_id or str(getattr(doc, "current_version", "1"))
        active_policy = EnginePolicyService.get_active_policy(db, doc.id)

        ProvenanceService.record_decryption_provenance(
            db=db,
            document_id=doc.id,
            document_version_id=doc_version_id,
            user_id=user.id,
            recipient_key_id=rec_key_id,
            recipient_key_version=rec_key_ver,
            device_id=device_id,
            decryption_session_id=session.id,
            policy_id=active_policy.id if active_policy else "EMERGENCY",
            policy_version=active_policy.policy_version if active_policy else 1,
            access_type="EMERGENCY",
            approval_request_id=None,
            emergency_access_request_id=request.id,
            document_plaintext_sha256=doc.plaintext_sha256,
            document_ciphertext_sha256=doc.ciphertext_sha256,
        )

        # 8. Mark request USED and session COMPLETED
        request.status = "USED"
        request.completed_at = now

        session.status = "COMPLETED"
        session.completed_at = now
        session.ended_at = now
        db.commit()

        AuditService.log_event(
            db=db,
            event_type="EMERGENCY_ACCESS_USED",
            user_id=user.id,
            document_id=doc.id,
            session_id=session.id,
            metadata={
                "emergency_request_id": request.id,
                "approver_id": request.approver_user_id,
                "reason": request.reason,
                "decrypted_size_bytes": len(plaintext),
            },
        )
        return session, plaintext

    @classmethod
    def get_emergency_request(cls, db: Session, request_id: str, user: User) -> EmergencyAccessRequest:
        """Retrieves an emergency access request."""
        now = datetime.now(timezone.utc)
        request = db.query(EmergencyAccessRequest).filter(EmergencyAccessRequest.id == request_id).first()
        if not request:
            raise ValueError("Emergency access request not found.")

        if request.status == "REQUESTED" and now > cls._to_utc(request.expires_at):
            request.status = "EXPIRED"
            db.commit()


        is_requester = user.id == request.requester_user_id
        is_owner = request.document.owner_id == user.id
        is_officer_or_admin = user.role in [UserRole.ADMIN.value, UserRole.OFFICER.value]

        if not (is_requester or is_owner or is_officer_or_admin):
            raise PermissionError("Access denied to this emergency access request.")

        return request

    @classmethod
    def list_requests(cls, db: Session, user: User, document_id: Optional[str] = None) -> List[EmergencyAccessRequest]:
        """Lists emergency requests."""
        query = db.query(EmergencyAccessRequest)
        if document_id:
            query = query.filter(EmergencyAccessRequest.document_id == document_id)
        if user.role not in [UserRole.ADMIN.value, UserRole.OFFICER.value]:
            query = query.filter(EmergencyAccessRequest.requester_user_id == user.id)
        return query.order_by(EmergencyAccessRequest.created_at.desc()).all()
