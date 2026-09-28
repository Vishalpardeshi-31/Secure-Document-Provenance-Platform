import os
import re
import uuid
import logging
from typing import List, Tuple, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.document import Document
from app.models.document_version import DocumentVersion
from app.models.document_recipient import DocumentRecipient
from app.models.access_policy import AccessPolicy
from app.models.user import User
from app.models.role import UserRole
from app.config.settings import settings
from app.security.crypto_service import CryptoService
from app.security.key_management_service import KeyManagementService
from app.security.recipient_key_manager import RecipientKeyManager
from app.services.document_storage_service import DocumentStorageService
from app.services.audit_service import AuditService

logger = logging.getLogger("secure_document_platform.document_service")


class DocumentService:
    ALLOWED_EXTENSIONS = {
        "pdf", "docx", "xlsx", "pptx", "txt", "csv", "json", "png", "jpg", "jpeg", "tiff", "zip"
    }

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitizes user-provided filename to prevent path traversal or filesystem attacks."""
        base = os.path.basename(filename).strip()
        clean = re.sub(r"[^\w\s\.\-_]", "_", base)
        if not clean or clean.startswith("."):
            clean = f"document_{uuid.uuid4().hex[:8]}"
        return clean[:255]

    @staticmethod
    def validate_upload(filename: str, content: bytes, mime_type: Optional[str] = None) -> None:
        """Validates filename extension, file size, and basic integrity constraints."""
        sanitized = DocumentService.sanitize_filename(filename)
        ext = sanitized.rsplit(".", 1)[-1].lower() if "." in sanitized else ""

        if ext not in DocumentService.ALLOWED_EXTENSIONS:
            raise ValueError(
                f"File extension '{ext}' is not permitted. Allowed extensions: {', '.join(sorted(DocumentService.ALLOWED_EXTENSIONS))}"
            )

        max_bytes = settings.MAX_DOCUMENT_SIZE_MB * 1024 * 1024
        if len(content) == 0:
            raise ValueError("Uploaded file is empty (0 bytes).")
        if len(content) > max_bytes:
            raise ValueError(f"Uploaded file exceeds maximum permitted size of {settings.MAX_DOCUMENT_SIZE_MB} MB.")

    @staticmethod
    def upload_and_encrypt_document(
        db: Session,
        owner: User,
        original_filename: str,
        content: bytes,
        mime_type: Optional[str] = None,
        title: Optional[str] = None,
        classification: str = "RESTRICTED",
        recipient_ids: Optional[List[str]] = None,
        policy_data: Optional[Dict[str, Any]] = None,
    ) -> Document:
        """Executes the complete transactional document encryption and multi-recipient key wrapping workflow:
        
        1. Validate file constraints.
        2. Atomically validate all requested recipients:
           - User exists and is active.
           - User has an ACTIVE ML-KEM-768 key pair provisioned.
           - If ANY recipient is invalid, immediately fail without partial distribution.
        3. Record DOCUMENT_UPLOAD_STARTED audit event.
        4. Create initial document record with status=ENCRYPTING.
        5. Generate a cryptographically random 256-bit DEK.
        6. Encrypt document once using AES-256-GCM.
        7. Wrap DEK under server KEK (for Phase 3 compatibility/recovery).
        8. For each validated recipient:
           - Wrap DEK using recipient's public key (ML-KEM-768 + HKDF-SHA256 + AES-256-GCM).
           - Create DocumentRecipient record with unique encapsulation material.
        9. Store ciphertext to isolated storage directory.
        10. Update document metadata and status=ENCRYPTED.
        11. Commit all records atomically.
        12. Record audit events (DOCUMENT_ENCRYPTED, DOCUMENT_MULTI_RECIPIENT_ENCRYPTED, DOCUMENT_RECIPIENT_ADDED).
        
        Failure handling: If storage or database fails, cleans up any orphaned artifacts
        and updates or rolls back status.
        """
        # Step 1: Validate file
        clean_filename = DocumentService.sanitize_filename(original_filename)
        effective_mime = mime_type or "application/octet-stream"
        DocumentService.validate_upload(clean_filename, content, effective_mime)

        # Step 1b: Pre-validate policy constraints
        if policy_data:
            p_from = policy_data.get("valid_from")
            p_until = policy_data.get("valid_until")
            if p_from and p_until and p_until <= p_from:
                raise ValueError("Access policy valid_until must be strictly after valid_from.")
            p_max = policy_data.get("max_decryptions")
            if p_max is not None and p_max < 1:
                raise ValueError("Access policy max_decryptions must be at least 1.")

        document_id = str(uuid.uuid4())
        doc_title = title.strip() if title and title.strip() else clean_filename

        # Step 2: Atomic Recipient Validation
        validated_recipients = []
        if recipient_ids:
            # Deduplicate while preserving order
            seen_ids = set()
            unique_recipient_ids = [rid for rid in recipient_ids if not (rid in seen_ids or seen_ids.add(rid))]

            for rid in unique_recipient_ids:
                rec_user = db.query(User).filter(User.id == rid).first()
                if not rec_user:
                    AuditService.log_event(
                        db=db,
                        event_type="DOCUMENT_RECIPIENT_DISTRIBUTION_FAILED",
                        user_id=owner.id,
                        metadata={"reason": f"Recipient ID '{rid}' does not exist."},
                    )
                    raise ValueError(f"Recipient with ID '{rid}' does not exist.")

                if not rec_user.is_active:
                    AuditService.log_event(
                        db=db,
                        event_type="DOCUMENT_RECIPIENT_DISTRIBUTION_FAILED",
                        user_id=owner.id,
                        metadata={"reason": f"Recipient '{rec_user.username}' is inactive."},
                    )
                    raise ValueError(f"Recipient '{rec_user.username}' is inactive.")

                active_key = RecipientKeyManager.get_active_key(db, rec_user.id)
                if not active_key:
                    AuditService.log_event(
                        db=db,
                        event_type="DOCUMENT_RECIPIENT_DISTRIBUTION_FAILED",
                        user_id=owner.id,
                        metadata={"reason": f"Recipient '{rec_user.username}' has no active cryptographic key."},
                    )
                    raise ValueError(f"Recipient '{rec_user.username}' has no active cryptographic key provisioned.")

                validated_recipients.append((rec_user, active_key))

        # Step 3: Audit start
        AuditService.log_event(
            db=db,
            event_type="DOCUMENT_UPLOAD_STARTED",
            user_id=owner.id,
            metadata={
                "document_id": document_id,
                "original_filename": clean_filename,
                "original_size_bytes": len(content),
                "recipient_count": len(validated_recipients),
            },
        )

        is_v2 = bool(validated_recipients)
        km_version = 2 if is_v2 else 1
        proto_version = "SDP-CRYPTO-V2" if is_v2 else "SDP-CRYPTO-V1"

        # Step 4: Create initial DB entry
        doc = Document(
            id=document_id,
            owner_id=owner.id,
            title=doc_title,
            original_filename=clean_filename,
            mime_type=effective_mime,
            original_size_bytes=len(content),
            encrypted_size_bytes=0,
            storage_reference="",
            plaintext_sha256="",
            ciphertext_sha256="",
            encryption_algorithm="AES-256-GCM",
            key_encryption_algorithm="ML-KEM-768+HKDF-SHA256+AES-256-GCM" if is_v2 else "AES-256-GCM-KEK",
            key_management_version=km_version,
            protocol_version=proto_version,
            nonce="",
            encrypted_dek="",
            classification=classification,
            status="ENCRYPTING",
        )
        db.add(doc)
        db.commit()
        db.refresh(doc)

        storage_ref: Optional[str] = None

        try:
            # Step 5: Generate fresh 256-bit DEK via CSPRNG
            dek = CryptoService.generate_dek()
            nonce = CryptoService.generate_nonce()

            # Step 6: Calculate SHA-256 of plaintext
            plaintext_sha256 = CryptoService.calculate_sha256(content)

            # Step 7: Encrypt plaintext using AES-256-GCM with canonical AAD
            from app.crypto.aad import build_document_aad
            if is_v2:
                aad = build_document_aad(document_id=doc.id, document_version_id="1", protocol_version=proto_version)
            else:
                aad = f"SDPP-DOC:{document_id}".encode("utf-8")

            ciphertext = CryptoService.encrypt_bytes(
                key=dek,
                nonce=nonce,
                plaintext=content,
                associated_data=aad,
            )

            # Step 8: Key wrapping
            wrapped_dek_b64 = ""
            if not is_v2:
                # Phase 3 legacy compatibility: wrap DEK using server KEK
                wrapped_dek_b64 = KeyManagementService.wrap_dek(dek)

            # Step 9: Multi-recipient key wrapping (ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM)
            for rec_user, active_key in validated_recipients:
                enc_key_b64, wrap_nonce_b64, rec_wrapped_dek_b64, algo = KeyManagementService.wrap_dek_for_recipient(
                    dek=dek,
                    recipient_public_key_b64=active_key.public_key,
                    document_id=doc.id,
                    document_version_id="1",
                    recipient_user_id=rec_user.id,
                    recipient_key_id=active_key.id,
                    recipient_key_version=active_key.key_version,
                    protocol_version=proto_version,
                )
                doc_recipient = DocumentRecipient(
                    document_id=doc.id,
                    user_id=rec_user.id,
                    permission_level="READ",
                    recipient_key_id=active_key.id,
                    recipient_key_version=active_key.key_version,
                    key_algorithm=algo,
                    kem_algorithm="ML-KEM-768",
                    kem_ciphertext=enc_key_b64,
                    encapsulated_key=enc_key_b64,
                    kdf_algorithm="HKDF",
                    kdf_hash="SHA-256",
                    kdf_info_version="SDP-DEK-WRAP-v1",
                    wrap_algorithm="AES-256-GCM",
                    wrapped_dek=rec_wrapped_dek_b64,
                    nonce=wrap_nonce_b64,
                    wrap_nonce=wrap_nonce_b64,
                    protocol_version=proto_version,
                    status="ACTIVE",
                )
                db.add(doc_recipient)

            # Step 10: Calculate SHA-256 of ciphertext
            ciphertext_sha256 = CryptoService.calculate_sha256(ciphertext)

            # Step 11: Store ciphertext via DocumentStorageService
            storage_ref = DocumentStorageService.save_encrypted_bytes(ciphertext)

            # Step 12: Store metadata and mark successfully ENCRYPTED
            import base64
            doc.storage_reference = storage_ref
            doc.encrypted_size_bytes = len(ciphertext)
            doc.plaintext_sha256 = plaintext_sha256
            doc.ciphertext_sha256 = ciphertext_sha256
            doc.nonce = base64.b64encode(nonce).decode("ascii")
            doc.encrypted_dek = wrapped_dek_b64
            doc.status = "ENCRYPTED"

            # Create initial version 1 record
            version1 = DocumentVersion(
                document_id=doc.id,
                version_number=1,
                original_filename=clean_filename,
                encrypted_storage_reference=storage_ref,
                content_hash=plaintext_sha256,
            )
            db.add(version1)

            if policy_data:
                p_from = policy_data.get("valid_from")
                p_until = policy_data.get("valid_until")
                p_max = policy_data.get("max_decryptions")
                p_dev = bool(policy_data.get("require_registered_device", False))
                p_app = bool(policy_data.get("require_approval", False) or policy_data.get("require_multi_party_approval", False))
                p_mpa = bool(policy_data.get("require_multi_party_approval", p_app))
                p_req_app = policy_data.get("required_approvals") or 1
                p_app_roles = policy_data.get("eligible_approver_roles")
                app_roles_str = ",".join([r.strip().upper() for r in p_app_roles]) if isinstance(p_app_roles, list) else (p_app_roles if isinstance(p_app_roles, str) else None)
                p_emg_allow = bool(policy_data.get("allow_emergency_access", False))
                p_emg_roles = policy_data.get("eligible_emergency_roles")
                emg_roles_str = ",".join([r.strip().upper() for r in p_emg_roles]) if isinstance(p_emg_roles, list) else (p_emg_roles if isinstance(p_emg_roles, str) else None)
                p_emg_perm = policy_data.get("eligible_emergency_permission", "EMERGENCY_DECRYPT")
                p_emg_app_req = bool(policy_data.get("emergency_approval_required", True))
                p_emg_dur = policy_data.get("maximum_emergency_duration", 15)

                p_roles = policy_data.get("allowed_roles")
                roles_str = ",".join([r.strip().upper() for r in p_roles]) if isinstance(p_roles, list) else (p_roles if isinstance(p_roles, str) else None)
                policy_obj = AccessPolicy(
                    document_id=doc.id,
                    policy_version=1,
                    status="ACTIVE",
                    enabled=True,
                    valid_from=p_from,
                    valid_until=p_until,
                    expiration_time=p_until,
                    max_decryptions=p_max,
                    maximum_sessions=p_max,
                    one_time_decryption=(p_max == 1 if p_max is not None else False),
                    require_registered_device=p_dev,
                    device_restriction=p_dev,
                    require_approval=p_app,
                    approval_requirement=p_app,
                    require_multi_party_approval=p_mpa,
                    required_approvals=p_req_app,
                    eligible_approver_roles=app_roles_str,
                    allow_emergency_access=p_emg_allow,
                    eligible_emergency_roles=emg_roles_str,
                    eligible_emergency_permission=p_emg_perm,
                    emergency_approval_required=p_emg_app_req,
                    maximum_emergency_duration=p_emg_dur,
                    allowed_roles=roles_str,
                    consumed_decryptions=0,
                    created_by=owner.id,
                )
                db.add(policy_obj)
                db.flush()
                AuditService.log_event(
                    db=db,
                    event_type="POLICY_CREATED",
                    user_id=owner.id,
                    document_id=doc.id,
                    metadata={
                        "policy_id": policy_obj.id,
                        "policy_version": 1,
                        "valid_from": p_from.isoformat() if p_from else None,
                        "valid_until": p_until.isoformat() if p_until else None,
                        "max_decryptions": p_max,
                        "require_registered_device": p_dev,
                        "require_multi_party_approval": p_mpa,
                        "required_approvals": p_req_app,
                        "allow_emergency_access": p_emg_allow,
                        "allowed_roles": roles_str,
                    },
                )

            db.commit()
            db.refresh(doc)

            # Step 13: Log audit events
            AuditService.log_event(
                db=db,
                event_type="DOCUMENT_ENCRYPTED",
                user_id=owner.id,
                document_id=doc.id,
                metadata={
                    "original_filename": clean_filename,
                    "encryption_algorithm": doc.encryption_algorithm,
                    "plaintext_sha256": plaintext_sha256,
                    "ciphertext_sha256": ciphertext_sha256,
                    "original_size_bytes": doc.original_size_bytes,
                    "encrypted_size_bytes": doc.encrypted_size_bytes,
                },
            )

            if validated_recipients:
                AuditService.log_event(
                    db=db,
                    event_type="DOCUMENT_MULTI_RECIPIENT_ENCRYPTED",
                    user_id=owner.id,
                    document_id=doc.id,
                    metadata={
                        "recipient_count": len(validated_recipients),
                        "recipient_ids": [r[0].id for r in validated_recipients],
                    },
                )
                for rec_user, active_key in validated_recipients:
                    AuditService.log_event(
                        db=db,
                        event_type="DOCUMENT_RECIPIENT_ADDED",
                        user_id=owner.id,
                        document_id=doc.id,
                        metadata={
                            "recipient_id": rec_user.id,
                            "recipient_username": rec_user.username,
                            "key_version": active_key.key_version,
                            "algorithm": active_key.algorithm,
                        },
                    )

            return doc

        except Exception as exc:
            logger.error(f"Document encryption failed for ID {document_id}: {exc}", exc_info=True)
            if storage_ref:
                DocumentStorageService.delete_encrypted_bytes(storage_ref)

            doc.status = "FAILED"
            try:
                db.commit()
            except Exception:
                db.rollback()

            AuditService.log_event(
                db=db,
                event_type="DOCUMENT_ENCRYPTION_FAILED",
                user_id=owner.id,
                document_id=document_id,
                metadata={
                    "error_category": type(exc).__name__,
                },
            )
            raise ValueError(f"Failed to encrypt and store document: {exc}")

    @staticmethod
    def list_documents(
        db: Session,
        user: User,
        offset: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Document], int]:
        """Lists documents according to role boundaries:
        - ADMIN: can view all documents
        - OFFICER: can view documents they uploaded/own
        - RECIPIENT: can view documents distributed to them with ACTIVE recipient status
        - AUDITOR: cannot view unshared documents (empty)
        """
        query = db.query(Document)

        if user.role == UserRole.ADMIN.value:
            pass  # Admin sees all
        elif user.role == UserRole.OFFICER.value:
            query = query.filter(Document.owner_id == user.id)
        elif user.role == UserRole.RECIPIENT.value:
            query = (
                query.join(DocumentRecipient, DocumentRecipient.document_id == Document.id)
                .filter(
                    DocumentRecipient.user_id == user.id,
                    DocumentRecipient.status == "ACTIVE",
                )
            )
        else:
            # Auditor does not view documents
            query = query.filter(Document.owner_id == user.id)

        total = query.count()
        docs = query.order_by(desc(Document.created_at)).offset(offset).limit(limit).all()
        return docs, total

    @staticmethod
    def get_document(db: Session, document_id: str, user: User) -> Optional[Document]:
        """Retrieves document metadata if the user is authorized."""
        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            return None

        if user.role == UserRole.ADMIN.value or doc.owner_id == user.id:
            return doc

        if user.role == UserRole.RECIPIENT.value:
            # Check if user is an active recipient
            is_active_recipient = any(
                r.user_id == user.id and r.status == "ACTIVE" for r in doc.recipients
            )
            if is_active_recipient:
                return doc

        return None

    @staticmethod
    def delete_document(db: Session, document_id: str, user: User) -> bool:
        """Deletes encrypted artifact from storage and document record from database."""
        # Only ADMIN or owner OFFICER can delete
        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            return False

        if user.role != UserRole.ADMIN.value and doc.owner_id != user.id:
            return False

        storage_ref = doc.storage_reference
        if storage_ref:
            DocumentStorageService.delete_encrypted_bytes(storage_ref)

        db.delete(doc)
        db.commit()

        AuditService.log_event(
            db=db,
            event_type="DOCUMENT_DELETED",
            user_id=user.id,
            document_id=document_id,
            metadata={"original_filename": doc.original_filename},
        )
        return True

    @staticmethod
    def format_document_response(doc: Document) -> Dict[str, Any]:
        """Formats Document ORM object into safe dictionary for DocumentResponse schema.
        
        Strictly excludes internal storage paths, raw DEKs, and private keys.
        """
        recipients_summary = [
            {
                "recipient_id": r.user_id,
                "username": r.user.username if r.user else None,
                "recipient_key_version": r.recipient_key_version,
                "key_algorithm": r.key_algorithm,
                "status": r.status,
                "granted_at": r.granted_at,
            }
            for r in doc.recipients
        ]
        policy_info = None
        if doc.access_policies:
            p = next((ap for ap in doc.access_policies if ap.enabled), doc.access_policies[0] if doc.access_policies else None)
            if p:
                policy_info = {
                    "id": p.id,
                    "document_id": p.document_id,
                    "enabled": p.enabled,
                    "valid_from": p.valid_from,
                    "valid_until": p.valid_until,
                    "max_decryptions": p.max_decryptions,
                    "require_registered_device": p.require_registered_device,
                    "require_approval": p.require_approval,
                    "created_by": p.created_by,
                    "created_at": p.created_at,
                    "updated_at": p.updated_at,
                }

        return {
            "id": doc.id,
            "title": doc.title,
            "original_filename": doc.original_filename,
            "mime_type": doc.mime_type,
            "original_size_bytes": doc.original_size_bytes,
            "encrypted_size_bytes": doc.encrypted_size_bytes,
            "plaintext_sha256": doc.plaintext_sha256,
            "ciphertext_sha256": doc.ciphertext_sha256,
            "encryption_algorithm": doc.encryption_algorithm,
            "classification": doc.classification,
            "status": doc.status,
            "owner_id": doc.owner_id,
            "recipients": recipients_summary,
            "recipient_count": len(recipients_summary),
            "policy": policy_info,
            "created_at": doc.created_at,
            "updated_at": doc.updated_at,
        }
