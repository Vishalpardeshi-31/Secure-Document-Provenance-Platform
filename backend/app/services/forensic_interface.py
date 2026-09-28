"""Forensic Fingerprinting Preparation Interface (Phase 12 Real Implementation).

Provides recipient-specific, session-bound invisible forensic fingerprinting
for controlled document rendering in secure viewer sessions.
"""
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger("secure_document_platform.forensic_provider")


@dataclass(frozen=True)
class ForensicFingerprintContext:
    """Carries complete viewer/provenance session context for downstream forensic fingerprinting."""
    document_id: str
    document_version_id: str
    user_id: str
    recipient_identity: str
    decryption_session_id: str
    viewer_session_id: str
    provenance_event_id: Optional[str]
    timestamp: datetime
    rendering_context: Optional[Dict[str, Any]] = None


class ForensicFingerprintProvider:
    """Enterprise forensic fingerprint provider embedding session-bound watermarks."""

    @classmethod
    def prepare_document_rendering(
        cls,
        content: bytes,
        mime_type: str,
        context: ForensicFingerprintContext,
        db: Optional[Any] = None,
        filename: str = "document",
    ) -> bytes:
        """Embeds a unique cryptographic forensic fingerprint into rendered content.
        
        Guarantees:
        - Decrypted content is processed strictly in-memory.
        - The original source document is never modified on disk.
        - Fail-closed: Any embedding failure raises an exception and blocks content delivery.
        """
        from app.forensic.derivation import FingerprintDerivationService
        from app.forensic.embedding import FingerprintEmbeddingService
        from app.services.audit_service import AuditService

        try:
            if db is not None:
                from app.models.viewer_session import ViewerSession
                from app.forensic.service import ForensicService

                vs = db.query(ViewerSession).filter(ViewerSession.id == context.viewer_session_id).first()
                if vs:
                    fp_rec, derived = ForensicService.get_or_create_fingerprint(db, vs)
                else:
                    derived = FingerprintDerivationService.derive_fingerprint(
                        document_id=context.document_id,
                        document_version_id=context.document_version_id,
                        recipient_user_id=context.user_id,
                        decryption_session_id=context.decryption_session_id,
                        viewer_session_id=context.viewer_session_id,
                        provenance_event_id=context.provenance_event_id or "NO-PROVENANCE",
                    )
            else:
                derived = FingerprintDerivationService.derive_fingerprint(
                    document_id=context.document_id,
                    document_version_id=context.document_version_id,
                    recipient_user_id=context.user_id,
                    decryption_session_id=context.decryption_session_id,
                    viewer_session_id=context.viewer_session_id,
                    provenance_event_id=context.provenance_event_id or "NO-PROVENANCE",
                )

            fingerprinted_bytes, _ = FingerprintEmbeddingService.embed_fingerprint(
                content=content,
                mime_type=mime_type,
                filename=filename,
                derived=derived,
            )

            if db is not None:
                try:
                    AuditService.log_event(
                        db=db,
                        event_type="FORENSIC_EMBEDDING_COMPLETED",
                        user_id=context.user_id,
                        document_id=context.document_id,
                        session_id=context.decryption_session_id,
                        metadata={
                            "viewer_session_id": context.viewer_session_id,
                            "fingerprint_token": derived.fingerprint_token,
                            "mime_type": mime_type,
                        },
                    )
                except Exception as ae:
                    logger.warning(f"Could not record audit event: {ae}")

            return fingerprinted_bytes

        except Exception as e:
            logger.error(f"Forensic embedding failed for session {context.viewer_session_id}: {e}", exc_info=True)
            if db is not None:
                try:
                    from app.services.audit_service import AuditService
                    AuditService.log_event(
                        db=db,
                        event_type="FORENSIC_EMBEDDING_FAILED",
                        user_id=context.user_id,
                        document_id=context.document_id,
                        session_id=context.decryption_session_id,
                        metadata={
                            "viewer_session_id": context.viewer_session_id,
                            "error": str(e),
                        },
                    )
                except Exception:
                    pass
            # Fail closed: never silently downgrade to unprotected viewing
            raise RuntimeError(f"FORENSIC_EMBEDDING_FAILED: Could not embed session forensic fingerprint: {str(e)}") from e
