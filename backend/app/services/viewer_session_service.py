import base64
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session

from app.models.viewer_session import ViewerSession
from app.models.decryption_session import DecryptionSession
from app.models.document import Document
from app.models.document_recipient import DocumentRecipient
from app.models.recipient_key import RecipientKey
from app.models.user import User
from app.provenance.models import ProvenanceRecord
from app.security.crypto_service import CryptoService
from app.security.key_management_service import KeyManagementService
from app.security.recipient_key_manager import RecipientKeyManager
from app.services.document_storage_service import DocumentStorageService
from app.services.audit_service import AuditService
from app.services.decryption_service import DecryptionService
from app.services.forensic_interface import (
    ForensicFingerprintContext,
    ForensicFingerprintProvider,
)
from app.crypto.aad import build_document_aad

logger = logging.getLogger("secure_document_platform.viewer_service")


class ViewerSessionService:
    """Manages secure document viewing session lifecycle, access control, and controlled content delivery."""

    DEFAULT_DURATION_SECONDS = 900  # 15 minutes
    MAX_DURATION_SECONDS = 3600  # 60 minutes
    MIN_DURATION_SECONDS = 60  # 1 minute

    SUPPORTED_EXTENSIONS = {"pdf", "txt", "json", "csv", "md", "png", "jpg", "jpeg"}
    SUPPORTED_MIME_TYPES = {
        "application/pdf",
        "text/plain",
        "application/json",
        "text/csv",
        "text/markdown",
        "image/png",
        "image/jpeg",
    }

    @staticmethod
    def _to_utc(dt: datetime) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @classmethod
    def create_viewer_session(
        cls,
        db: Session,
        document_id: str,
        user: User,
        device_id: Optional[str] = None,
        approval_request_id: Optional[str] = None,
        emergency_request_id: Optional[str] = None,
        duration_seconds: int = DEFAULT_DURATION_SECONDS,
    ) -> Tuple[ViewerSession, DecryptionSession, Optional[ProvenanceRecord]]:
        """Atomically authenticates, authorizes, decrypts, signs provenance, and creates a secure viewer session."""
        now = datetime.now(timezone.utc)

        # 1. Bounds-check duration
        bounded_duration = max(cls.MIN_DURATION_SECONDS, min(cls.MAX_DURATION_SECONDS, duration_seconds))
        expires_at = now + timedelta(seconds=bounded_duration)

        # 2. Execute existing authoritative decryption pipeline
        # This enforces identity, recipient authorization, policy checks, approvals/emergency,
        # AES-256-GCM decryption, and ML-DSA-65 provenance signing & chaining.
        dec_session, _ = DecryptionService.request_and_decrypt(
            db=db,
            document_id=document_id,
            user=user,
            device_id=device_id,
            approval_request_id=approval_request_id,
            emergency_request_id=emergency_request_id,
        )

        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            raise ValueError("Document not found.")

        # 3. Retrieve associated provenance event
        prov_record = (
            db.query(ProvenanceRecord)
            .filter(ProvenanceRecord.decryption_session_id == dec_session.id)
            .order_by(ProvenanceRecord.created_at.desc())
            .first()
        )

        # 4. Construct ViewerSession
        viewer_session = ViewerSession(
            id=str(uuid.uuid4()),
            decryption_session_id=dec_session.id,
            provenance_event_id=prov_record.event_id if prov_record else None,
            document_id=doc.id,
            document_version_id=dec_session.version_id,
            user_id=user.id,
            device_id=device_id,
            status="ACTIVE",
            session_duration_seconds=bounded_duration,
            created_at=now,
            expires_at=expires_at,
            last_activity_at=now,
        )
        db.add(viewer_session)
        db.commit()
        db.refresh(viewer_session)

        # 5. Record Audit Event
        AuditService.log_event(
            db=db,
            event_type="VIEWER_SESSION_CREATED",
            user_id=user.id,
            document_id=doc.id,
            session_id=dec_session.id,
            metadata={
                "viewer_session_id": viewer_session.id,
                "decryption_session_id": dec_session.id,
                "provenance_event_id": viewer_session.provenance_event_id,
                "device_id": device_id,
                "expires_at": expires_at.isoformat(),
                "duration_seconds": bounded_duration,
            },
        )

        return viewer_session, dec_session, prov_record

    @classmethod
    def get_viewer_session(
        cls,
        db: Session,
        session_id: str,
        user: User,
        device_id: Optional[str] = None,
        allow_expired: bool = False,
    ) -> ViewerSession:
        """Retrieves and strictly validates an active viewer session against user, device, and expiration."""
        now = datetime.now(timezone.utc)

        session = db.query(ViewerSession).filter(ViewerSession.id == session_id).first()
        if not session:
            AuditService.log_event(
                db=db,
                event_type="VIEWER_SESSION_REJECTED",
                user_id=user.id,
                metadata={"viewer_session_id": session_id, "reason": "VIEWER_SESSION_NOT_FOUND"},
            )
            raise ValueError("VIEWER_SESSION_NOT_FOUND: Viewer session does not exist.")

        # Validate user ownership
        if session.user_id != user.id:
            AuditService.log_event(
                db=db,
                event_type="VIEWER_SESSION_REJECTED",
                user_id=user.id,
                document_id=session.document_id,
                metadata={
                    "viewer_session_id": session_id,
                    "session_user_id": session.user_id,
                    "reason": "VIEWER_UNAUTHORIZED",
                },
            )
            raise PermissionError("VIEWER_UNAUTHORIZED: Access to this viewer session is not permitted.")

        # Validate device binding
        if session.device_id and session.device_id != device_id:
            AuditService.log_event(
                db=db,
                event_type="VIEWER_SESSION_REJECTED",
                user_id=user.id,
                document_id=session.document_id,
                metadata={
                    "viewer_session_id": session_id,
                    "expected_device_id": session.device_id,
                    "supplied_device_id": device_id,
                    "reason": "VIEWER_DEVICE_MISMATCH",
                },
            )
            raise PermissionError("VIEWER_DEVICE_MISMATCH: Viewer session is bound to a different registered device.")

        # Check document revocation
        doc = db.query(Document).filter(Document.id == session.document_id).first()
        if not doc or doc.status == "REVOKED":
            session.status = "REVOKED"
            db.commit()
            AuditService.log_event(
                db=db,
                event_type="VIEWER_SESSION_REJECTED",
                user_id=user.id,
                document_id=session.document_id,
                metadata={"viewer_session_id": session_id, "reason": "VIEWER_DOCUMENT_REVOKED"},
            )
            raise PermissionError("VIEWER_DOCUMENT_REVOKED: The requested document has been administratively revoked.")

        # Check administrative/session revocation
        if session.status == "REVOKED":
            raise PermissionError("VIEWER_SESSION_REVOKED: Viewer session has been revoked.")

        # Process expiration timestamp
        if now > cls._to_utc(session.expires_at):
            if session.status != "EXPIRED":
                session.status = "EXPIRED"
                db.commit()
                AuditService.log_event(
                    db=db,
                    event_type="VIEWER_SESSION_EXPIRED",
                    user_id=user.id,
                    document_id=session.document_id,
                    metadata={"viewer_session_id": session_id},
                )

        if not allow_expired:
            if session.status == "COMPLETED":
                raise PermissionError("VIEWER_SESSION_CLOSED: Viewer session has been closed.")
            if session.status == "EXPIRED" or now > cls._to_utc(session.expires_at):
                raise PermissionError("VIEWER_SESSION_EXPIRED: Viewer session has expired.")

        return session

    @classmethod
    def heartbeat(
        cls,
        db: Session,
        session_id: str,
        user: User,
        device_id: Optional[str] = None,
    ) -> ViewerSession:
        """Lightweight heartbeat updating last_activity_at without extending expires_at indefinitely."""
        now = datetime.now(timezone.utc)
        session = cls.get_viewer_session(db, session_id, user, device_id, allow_expired=False)
        session.last_activity_at = now
        db.commit()
        return session

    @classmethod
    def close_viewer_session(
        cls,
        db: Session,
        session_id: str,
        user: User,
        device_id: Optional[str] = None,
    ) -> ViewerSession:
        """Explicitly closes an active viewer session and marks status COMPLETED."""
        now = datetime.now(timezone.utc)
        session = cls.get_viewer_session(db, session_id, user, device_id, allow_expired=False)
        session.status = "COMPLETED"
        session.closed_at = now
        db.commit()

        AuditService.log_event(
            db=db,
            event_type="VIEWER_SESSION_CLOSED",
            user_id=user.id,
            document_id=session.document_id,
            metadata={"viewer_session_id": session_id},
        )
        return session

    @classmethod
    def get_session_content(
        cls,
        db: Session,
        session_id: str,
        user: User,
        device_id: Optional[str] = None,
    ) -> Tuple[bytes, str, str]:
        """Delivers decrypted document content strictly into memory for the active viewer session.
        
        Returns:
            Tuple of (plaintext_bytes, mime_type, original_filename).
        """
        now = datetime.now(timezone.utc)
        session = cls.get_viewer_session(db, session_id, user, device_id, allow_expired=False)
        doc = session.document

        # 1. Format validation
        ext = doc.original_filename.rsplit(".", 1)[-1].lower() if "." in doc.original_filename else ""
        ext_supported = ext in cls.SUPPORTED_EXTENSIONS
        mime_supported = doc.mime_type in cls.SUPPORTED_MIME_TYPES if doc.mime_type else False
        is_supported = ext_supported if ext else mime_supported
        if not is_supported:
            AuditService.log_event(
                db=db,
                event_type="VIEWER_SESSION_REJECTED",
                user_id=user.id,
                document_id=doc.id,
                metadata={
                    "viewer_session_id": session.id,
                    "reason": "VIEWER_FORMAT_UNSUPPORTED",
                    "filename": doc.original_filename,
                    "mime_type": doc.mime_type,
                },
            )
            raise ValueError(
                f"VIEWER_FORMAT_UNSUPPORTED: Document format (.{ext}) is not supported for inline secure viewing. "
                "Supported formats include PDF, TXT, JSON, CSV, MD, PNG, JPG."
            )

        # 2. Recover authorized DEK
        # Reuse existing KeyManagementService & RecipientKeyManager
        recipient = (
            db.query(DocumentRecipient)
            .filter(
                DocumentRecipient.document_id == doc.id,
                DocumentRecipient.user_id == user.id,
            )
            .first()
        )

        if doc.key_management_version == 1:
            recovered_dek = KeyManagementService.unwrap_dek(doc.encrypted_dek)
            aad = f"SDPP-DOC:{doc.id}".encode("utf-8")
        elif doc.key_management_version == 2:
            if recipient:
                key_record = (
                    db.query(RecipientKey)
                    .filter(
                        RecipientKey.user_id == user.id,
                        RecipientKey.key_version == recipient.recipient_key_version,
                    )
                    .first()
                )
                if not key_record:
                    raise ValueError("Recipient key version not found in database.")
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
            else:
                # Emergency break-glass session without explicit recipient assignment:
                # use authorized server KEK envelope
                recovered_dek = KeyManagementService.unwrap_dek(doc.encrypted_dek)

            aad = build_document_aad(
                document_id=doc.id,
                document_version_id="1",
                protocol_version=doc.protocol_version,
            )
        else:
            raise ValueError(f"Unsupported key management version: {doc.key_management_version}")

        # 3. Read ciphertext from protected storage and verify integrity
        ciphertext = DocumentStorageService.read_encrypted_bytes(doc.storage_reference)
        if CryptoService.calculate_sha256(ciphertext) != doc.ciphertext_sha256:
            raise ValueError("Ciphertext integrity verification failed (SHA-256 mismatch).")

        # 4. Authenticated AES-256-GCM decryption
        doc_nonce = base64.b64decode(doc.nonce)
        plaintext = CryptoService.decrypt_bytes(
            key=recovered_dek,
            nonce=doc_nonce,
            ciphertext_and_tag=ciphertext,
            associated_data=aad,
        )

        # 5. Verify plaintext integrity
        if CryptoService.calculate_sha256(plaintext) != doc.plaintext_sha256:
            raise ValueError("Plaintext integrity verification failed (SHA-256 mismatch).")

        # 6. Apply Forensic Fingerprinting Preparation extension point (Phase 11 preparation)
        context = ForensicFingerprintContext(
            document_id=doc.id,
            document_version_id=session.document_version_id,
            user_id=user.id,
            recipient_identity=user.username,
            decryption_session_id=session.decryption_session_id,
            viewer_session_id=session.id,
            provenance_event_id=session.provenance_event_id,
            timestamp=now,
        )
        effective_mime_type = doc.mime_type or "application/octet-stream"
        rendered_content = ForensicFingerprintProvider.prepare_document_rendering(
            content=plaintext,
            mime_type=effective_mime_type,
            context=context,
        )

        # 7. Update activity timestamp & record audit event
        session.last_activity_at = now
        db.commit()

        AuditService.log_event(
            db=db,
            event_type="VIEWER_SESSION_ACCESS",
            user_id=user.id,
            document_id=doc.id,
            metadata={
                "viewer_session_id": session.id,
                "content_size_bytes": len(rendered_content),
                "mime_type": effective_mime_type,
            },
        )

        return rendered_content, effective_mime_type, doc.original_filename
