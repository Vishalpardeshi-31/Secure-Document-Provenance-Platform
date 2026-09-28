import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.user import User
from app.models.role import UserRole
from app.models.document import Document
from app.models.viewer_session import ViewerSession
from app.models.decryption_session import DecryptionSession
from app.models.forensic_fingerprint import ForensicFingerprint
from app.provenance.models import ProvenanceRecord
from app.provenance.service import ProvenanceService
from app.services.audit_service import AuditService
from app.forensic.derivation import (
    FingerprintDerivationService,
    DerivedFingerprintMaterial,
)
from app.forensic.detection import (
    FingerprintDetectionService,
    DetectionResult,
)
from app.forensic.schemas import (
    ForensicDetectionResponse,
    AssociatedSessionInfo,
    ProvenanceCorrelationInfo,
)

logger = logging.getLogger("secure_document_platform.forensic_service")


class ForensicService:
    """Core enterprise orchestration service for forensic fingerprinting, detection, and provenance correlation."""

    @classmethod
    def get_or_create_fingerprint(
        cls,
        db: Session,
        viewer_session: ViewerSession,
    ) -> Tuple[ForensicFingerprint, DerivedFingerprintMaterial]:
        """Atomically retrieves or creates the unique cryptographic forensic fingerprint for a viewing session."""
        existing = (
            db.query(ForensicFingerprint)
            .filter(ForensicFingerprint.viewer_session_id == viewer_session.id)
            .first()
        )
        if existing:
            # Reconstruct derived material deterministically using the stored nonce
            derived = FingerprintDerivationService.derive_fingerprint(
                document_id=existing.document_id,
                document_version_id=existing.document_version_id,
                recipient_user_id=existing.recipient_user_id,
                decryption_session_id=existing.decryption_session_id,
                viewer_session_id=existing.viewer_session_id,
                provenance_event_id=existing.provenance_event_id,
                nonce=existing.fingerprint_nonce,
            )
            return existing, derived

        # Generate fresh derivation
        nonce = FingerprintDerivationService.generate_nonce()
        provenance_id = viewer_session.provenance_event_id or "GENESIS-OR-UNANCHORED"

        derived = FingerprintDerivationService.derive_fingerprint(
            document_id=viewer_session.document_id,
            document_version_id=viewer_session.document_version_id,
            recipient_user_id=viewer_session.user_id,
            decryption_session_id=viewer_session.decryption_session_id,
            viewer_session_id=viewer_session.id,
            provenance_event_id=provenance_id,
            nonce=nonce,
        )

        fingerprint_record = ForensicFingerprint(
            document_id=viewer_session.document_id,
            document_version_id=viewer_session.document_version_id,
            provenance_event_id=provenance_id,
            decryption_session_id=viewer_session.decryption_session_id,
            viewer_session_id=viewer_session.id,
            recipient_user_id=viewer_session.user_id,
            recipient_key_id=None,
            fingerprint_version=FingerprintDerivationService.FINGERPRINT_VERSION,
            fingerprint_algorithm=FingerprintDerivationService.ALGORITHM,
            fingerprint_token=derived.fingerprint_token,
            fingerprint_commitment=derived.fingerprint_commitment,
            fingerprint_nonce=derived.fingerprint_nonce,
            embedding_profile="PDF_DCT_SPREAD_SPECTRUM_V1",
            embedding_parameters_version=1,
            status="ACTIVE",
            created_at=datetime.now(timezone.utc),
        )
        db.add(fingerprint_record)
        db.commit()
        db.refresh(fingerprint_record)

        # Audit event
        AuditService.log_event(
            db=db,
            event_type="FORENSIC_FINGERPRINT_CREATED",
            user_id=viewer_session.user_id,
            document_id=viewer_session.document_id,
            session_id=viewer_session.decryption_session_id,
            metadata={
                "fingerprint_id": fingerprint_record.id,
                "fingerprint_token": fingerprint_record.fingerprint_token,
                "fingerprint_commitment": fingerprint_record.fingerprint_commitment,
                "viewer_session_id": viewer_session.id,
                "provenance_event_id": provenance_id,
            },
        )

        return fingerprint_record, derived

    @classmethod
    def investigate_evidence(
        cls,
        db: Session,
        evidence_bytes: bytes,
        filename: str,
        investigating_user: User,
        expected_document_id: Optional[str] = None,
    ) -> ForensicDetectionResponse:
        """Executes full forensic signal analysis and cryptographic provenance correlation.
        
        Strict Access Control: Only ADMIN or AUDITOR roles are permitted.
        """
        # Role check
        if investigating_user.role not in [UserRole.ADMIN.value, UserRole.AUDITOR.value]:
            AuditService.log_event(
                db=db,
                event_type="FORENSIC_DETECTION_FAILED",
                user_id=investigating_user.id,
                metadata={"reason": "UNAUTHORIZED_INVESTIGATION_ATTEMPT", "filename": filename},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Only authorized Administrators or Auditors can execute forensic leak investigations.",
            )

        now = datetime.now(timezone.utc)

        # Audit request
        AuditService.log_event(
            db=db,
            event_type="FORENSIC_DETECTION_REQUESTED",
            user_id=investigating_user.id,
            metadata={
                "filename": filename,
                "evidence_size_bytes": len(evidence_bytes),
                "expected_document_id": expected_document_id,
            },
        )

        # Run signal detection
        det_result: DetectionResult = FingerprintDetectionService.detect(evidence_bytes, filename=filename)

        if det_result.detection_status != "FINGERPRINT_DETECTED" or not det_result.candidate_token:
            AuditService.log_event(
                db=db,
                event_type="FORENSIC_DETECTION_COMPLETED",
                user_id=investigating_user.id,
                metadata={
                    "status": det_result.detection_status,
                    "filename": filename,
                    "diagnostics": det_result.diagnostics,
                },
            )
            return ForensicDetectionResponse(
                detection_status=det_result.detection_status,
                evidence_filename=filename,
                embedding_profile=det_result.embedding_profile,
                candidate_fingerprint_token=None,
                candidate_fingerprint_id=None,
                confidence_score=det_result.confidence_score,
                correlation=None,
                provenance=None,
                diagnostics=det_result.diagnostics,
                investigated_at=now,
                investigating_user_id=investigating_user.id,
            )

        # Look up candidate token in database
        fp_rec = (
            db.query(ForensicFingerprint)
            .filter(ForensicFingerprint.fingerprint_token == det_result.candidate_token)
            .first()
        )

        if not fp_rec:
            # Token detected from signal but not registered in this platform's database
            det_result.diagnostics["unregistered_token"] = det_result.candidate_token
            return ForensicDetectionResponse(
                detection_status="FINGERPRINT_DETECTED",
                evidence_filename=filename,
                fingerprint_version=1,
                embedding_profile=det_result.embedding_profile,
                candidate_fingerprint_token=det_result.candidate_token,
                candidate_fingerprint_id=None,
                confidence_score=det_result.confidence_score,
                correlation=None,
                provenance=None,
                diagnostics=det_result.diagnostics,
                investigated_at=now,
                investigating_user_id=investigating_user.id,
            )

        # Correlate with session and user metadata
        vs = fp_rec.viewer_session
        ds = fp_rec.decryption_session
        doc = fp_rec.document
        user = fp_rec.recipient_user

        correlation = AssociatedSessionInfo(
            viewer_session_id=fp_rec.viewer_session_id,
            decryption_session_id=fp_rec.decryption_session_id,
            recipient_user_id=user.id,
            recipient_username=user.username,
            recipient_email=user.email,
            recipient_department=user.department.name if user.department else None,
            device_id=vs.device_id if vs else None,
            device_name=vs.device.device_name if vs and vs.device else None,
            document_id=doc.id,
            document_title=doc.title,
            document_version_id=fp_rec.document_version_id,
            classification=doc.classification,
            session_created_at=vs.created_at.isoformat() if vs else ds.created_at.isoformat(),
            session_expires_at=vs.expires_at.isoformat() if vs else ds.expires_at.isoformat(),
            session_status=vs.status if vs else ds.status,
        )

        # Correlate and verify cryptographic provenance
        prov_info: Optional[ProvenanceCorrelationInfo] = None
        if fp_rec.provenance_event_id:
            prov_rec = (
                db.query(ProvenanceRecord)
                .filter(ProvenanceRecord.event_id == fp_rec.provenance_event_id)
                .first()
            )
            if prov_rec:
                # 1. Verify ML-DSA-65 signature on provenance record
                try:
                    sig_ver = ProvenanceService.verify_provenance(
                        db=db,
                        event_id=prov_rec.event_id,
                        verifying_user=investigating_user,
                    )
                    sig_verified = bool(getattr(sig_ver, "verified", getattr(sig_ver, "signature_valid", False)))
                except Exception as e:
                    logger.warning(f"Provenance signature verification failed: {e}")
                    sig_verified = False

                # 2. Verify ledger anchor
                try:
                    anchor_res = ProvenanceService.verify_ledger_anchor(
                        db=db,
                        event_id=prov_rec.event_id,
                        verifying_user=investigating_user,
                    )
                    anchored = anchor_res.is_anchored
                    tx_id = anchor_res.transaction_id
                    hash_matched = anchor_res.hash_matched
                except Exception as e:
                    logger.warning(f"Ledger anchor verification failed: {e}")
                    anchored = False
                    tx_id = None
                    hash_matched = False

                prov_info = ProvenanceCorrelationInfo(
                    event_id=prov_rec.event_id,
                    chain_id=prov_rec.chain_id,
                    chain_sequence=prov_rec.chain_sequence,
                    chain_hash=prov_rec.chain_hash,
                    previous_record_hash=prov_rec.previous_record_hash,
                    canonical_record_hash=prov_rec.canonical_record_hash,
                    signature_algorithm=prov_rec.signature_algorithm,
                    signature_key_id=prov_rec.signature_key_id,
                    signature_verified=sig_verified,
                    chain_link_verified=True,
                    ledger_anchored=anchored,
                    ledger_transaction_id=tx_id,
                    ledger_hash_matched=hash_matched,
                    event_timestamp=str(prov_rec.event_timestamp),
                )

        # Log completion audit event
        AuditService.log_event(
            db=db,
            event_type="FORENSIC_DETECTION_COMPLETED",
            user_id=investigating_user.id,
            document_id=doc.id,
            session_id=fp_rec.decryption_session_id,
            metadata={
                "fingerprint_id": fp_rec.id,
                "fingerprint_token": fp_rec.fingerprint_token,
                "confidence_score": det_result.confidence_score,
                "associated_recipient": user.username,
                "viewer_session_id": fp_rec.viewer_session_id,
                "provenance_event_id": fp_rec.provenance_event_id,
            },
        )

        return ForensicDetectionResponse(
            detection_status="FINGERPRINT_DETECTED",
            evidence_filename=filename,
            fingerprint_version=fp_rec.fingerprint_version,
            embedding_profile=fp_rec.embedding_profile,
            candidate_fingerprint_token=fp_rec.fingerprint_token,
            candidate_fingerprint_id=fp_rec.id,
            confidence_score=det_result.confidence_score,
            correlation=correlation,
            provenance=prov_info,
            diagnostics=det_result.diagnostics,
            investigated_at=now,
            investigating_user_id=investigating_user.id,
        )

    @classmethod
    def get_fingerprint_by_id(cls, db: Session, fingerprint_id: str, requesting_user: User) -> ForensicFingerprint:
        """Retrieves a forensic fingerprint record. Restricts access to ADMIN and AUDITOR roles."""
        if requesting_user.role not in [UserRole.ADMIN.value, UserRole.AUDITOR.value]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
        fp = db.query(ForensicFingerprint).filter(ForensicFingerprint.id == fingerprint_id).first()
        if not fp:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic fingerprint not found.")
        return fp

    @classmethod
    def get_fingerprint_for_viewer_session(cls, db: Session, viewer_session_id: str, requesting_user: User) -> ForensicFingerprint:
        """Retrieves the forensic fingerprint record for a viewer session. Restricts access to ADMIN and AUDITOR."""
        if requesting_user.role not in [UserRole.ADMIN.value, UserRole.AUDITOR.value]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
        fp = db.query(ForensicFingerprint).filter(ForensicFingerprint.viewer_session_id == viewer_session_id).first()
        if not fp:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic fingerprint not found for this session.")
        return fp
