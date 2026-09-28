import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.user import User
from app.models.role import UserRole
from app.models.document import Document
from app.models.forensic_fingerprint import ForensicFingerprint
from app.provenance.models import ProvenanceRecord
from app.models.investigation import (
    InvestigationCase,
    InvestigationEvidence,
    InvestigationCustodyEvent,
    InvestigationResult,
)
from app.investigation.schemas import (
    InvestigationCaseCreateRequest,
    InvestigationCaseResponse,
    InvestigationCaseDetailResponse,
    InvestigationEvidenceResponse,
    CustodyEventResponse,
    InvestigationResultResponse,
    TimelineEvent,
    InvestigationReportResponse,
)
from app.investigation.storage import EvidenceStorageService
from app.investigation.report import InvestigationReportGenerator
from app.forensic.detection import FingerprintDetectionService, DetectionResult
from app.provenance.service import ProvenanceService
from app.provenance.verification import ProvenanceVerificationService
from app.services.audit_service import AuditService

logger = logging.getLogger("secure_document_platform.investigation_service")


class InvestigationService:
    """Core domain service for digital leak investigation, forensic evidence analysis,
    and end-to-end cryptographic provenance attribution.
    """

    SUPPORTED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".bin"}
    SUPPORTED_MIME_TYPES = {
        "application/pdf",
        "image/png",
        "image/jpeg",
        "image/jpg",
        "image/webp",
        "image/bmp",
        "image/tiff",
        "application/octet-stream",
    }

    @classmethod
    def _check_investigator_role(cls, user: User) -> None:
        """Enforces that only ADMIN or AUDITOR roles can interact with investigations."""
        if user.role not in [UserRole.ADMIN.value, UserRole.AUDITOR.value]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Only ADMIN or AUDITOR roles may access forensic investigation workflows.",
            )

    @classmethod
    def create_case(
        cls,
        db: Session,
        request: InvestigationCaseCreateRequest,
        user: User,
    ) -> InvestigationCaseResponse:
        """Initializes a new formal investigation case."""
        cls._check_investigator_role(user)

        # Validate document ID if supplied
        if request.document_id:
            doc = db.query(Document).filter(Document.id == request.document_id).first()
            if not doc:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Referenced document '{request.document_id}' not found.",
                )

        now = datetime.now(timezone.utc)
        case_id = str(uuid.uuid4())
        date_str = now.strftime("%Y%m%d")
        case_ref = f"CASE-{date_str}-{uuid.uuid4().hex[:6].upper()}"

        case = InvestigationCase(
            id=case_id,
            case_reference=case_ref,
            title=request.title.strip(),
            description=request.description.strip() if request.description else None,
            created_by=user.id,
            document_id=request.document_id,
            document_version_id=request.document_version_id,
            status="OPEN",
            created_at=now,
            updated_at=now,
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        # Audit event
        AuditService.log_event(
            db=db,
            event_type="INVESTIGATION_CREATED",
            user_id=user.id,
            document_id=case.document_id,
            metadata={
                "case_id": case.id,
                "case_reference": case.case_reference,
                "title": case.title,
            },
        )

        return InvestigationCaseResponse(
            id=case.id,
            case_reference=case.case_reference,
            title=case.title,
            description=case.description,
            created_by=case.created_by,
            document_id=case.document_id,
            document_version_id=case.document_version_id,
            status=case.status,
            created_at=case.created_at,
            updated_at=case.updated_at,
            completed_at=case.completed_at,
            evidence_count=0,
            results_count=0,
        )

    @classmethod
    def list_cases(
        cls,
        db: Session,
        user: User,
        limit: int = 50,
        offset: int = 0,
    ) -> List[InvestigationCaseResponse]:
        """Lists investigation cases with pagination."""
        cls._check_investigator_role(user)

        cases = (
            db.query(InvestigationCase)
            .order_by(desc(InvestigationCase.created_at))
            .offset(offset)
            .limit(limit)
            .all()
        )

        responses: List[InvestigationCaseResponse] = []
        for c in cases:
            responses.append(
                InvestigationCaseResponse(
                    id=c.id,
                    case_reference=c.case_reference,
                    title=c.title,
                    description=c.description,
                    created_by=c.created_by,
                    document_id=c.document_id,
                    document_version_id=c.document_version_id,
                    evidence_filename=c.evidence_filename,
                    evidence_sha256=c.evidence_sha256,
                    evidence_size=c.evidence_size,
                    evidence_mime_type=c.evidence_mime_type,
                    status=c.status,
                    created_at=c.created_at,
                    updated_at=c.updated_at,
                    completed_at=c.completed_at,
                    evidence_count=len(c.evidence_items),
                    results_count=len(c.results),
                )
            )
        return responses

    @classmethod
    def get_case(cls, db: Session, case_id: str, user: User) -> InvestigationCase:
        """Retrieves raw case entity with validation."""
        cls._check_investigator_role(user)
        case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
        if not case:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation case '{case_id}' not found.",
            )
        return case

    @classmethod
    def upload_evidence(
        cls,
        db: Session,
        case_id: str,
        evidence_bytes: bytes,
        filename: str,
        mime_type: str,
        user: User,
    ) -> InvestigationEvidenceResponse:
        """Persists suspected leak evidence, records chain of custody, and updates case metadata."""
        cls._check_investigator_role(user)
        case = cls.get_case(db, case_id, user)

        if not evidence_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Evidence payload cannot be empty.",
            )

        # Validation: Max size 50MB
        if len(evidence_bytes) > 50 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Evidence exceeds maximum allowable size (50 MB).",
            )

        # Validate file format
        import os
        ext = os.path.splitext(filename)[1].lower()
        if ext not in cls.SUPPORTED_EXTENSIONS and mime_type not in cls.SUPPORTED_MIME_TYPES:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail=f"Unsupported evidence format: '{ext or mime_type}'. Supported: PDF, PNG, JPEG, WebP.",
            )

        # Save to isolated evidence storage
        try:
            storage_ref, sha256_hash = EvidenceStorageService.save_evidence_bytes(
                evidence_bytes=evidence_bytes,
                original_filename=filename,
            )
        except Exception as e:
            logger.error(f"Failed to persist evidence artifact: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal storage error during evidence persistence.",
            )

        now = datetime.now(timezone.utc)
        evidence_version = len(case.evidence_items) + 1
        evidence = InvestigationEvidence(
            id=str(uuid.uuid4()),
            case_id=case.id,
            original_filename=filename,
            mime_type=mime_type or "application/octet-stream",
            size_bytes=len(evidence_bytes),
            sha256=sha256_hash,
            storage_reference=storage_ref,
            uploaded_by=user.id,
            uploaded_at=now,
            evidence_version=evidence_version,
            processing_status="PENDING",
        )
        db.add(evidence)

        # Update case top-level evidence snapshot
        case.evidence_filename = filename
        case.evidence_sha256 = sha256_hash
        case.evidence_size = len(evidence_bytes)
        case.evidence_mime_type = mime_type
        case.updated_at = now

        # Chain of custody events
        custody_upload = InvestigationCustodyEvent(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            actor_id=user.id,
            action="EVIDENCE_UPLOADED",
            evidence_sha256=sha256_hash,
            metadata_json=json.dumps({
                "original_filename": filename,
                "mime_type": mime_type,
                "size_bytes": len(evidence_bytes),
                "evidence_version": evidence_version,
            }),
            created_at=now,
        )
        custody_hash = InvestigationCustodyEvent(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            actor_id=user.id,
            action="EVIDENCE_HASHED",
            evidence_sha256=sha256_hash,
            metadata_json=json.dumps({"hash_algorithm": "SHA-256", "sha256": sha256_hash}),
            created_at=now,
        )
        db.add(custody_upload)
        db.add(custody_hash)
        db.commit()
        db.refresh(evidence)

        # Audit event
        AuditService.log_event(
            db=db,
            event_type="EVIDENCE_UPLOADED",
            user_id=user.id,
            document_id=case.document_id,
            metadata={
                "case_id": case.id,
                "evidence_id": evidence.id,
                "sha256": sha256_hash,
                "filename": filename,
            },
        )

        return InvestigationEvidenceResponse.model_validate(evidence)

    @classmethod
    def analyze_evidence(
        cls,
        db: Session,
        case_id: str,
        evidence_id: Optional[str],
        user: User,
    ) -> InvestigationResultResponse:
        """Executes the complete forensic signal analysis and cryptographic provenance verification pipeline."""
        cls._check_investigator_role(user)
        case = cls.get_case(db, case_id, user)

        # Select evidence
        if evidence_id:
            evidence = (
                db.query(InvestigationEvidence)
                .filter(InvestigationEvidence.id == evidence_id, InvestigationEvidence.case_id == case.id)
                .first()
            )
        else:
            evidence = (
                db.query(InvestigationEvidence)
                .filter(InvestigationEvidence.case_id == case.id)
                .order_by(desc(InvestigationEvidence.uploaded_at))
                .first()
            )

        if not evidence:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No evidence artifact found for this investigation case.",
            )

        now = datetime.now(timezone.utc)
        case.status = "ANALYZING"
        evidence.processing_status = "ANALYZING"
        db.commit()

        # Log custody & audit for analysis start
        db.add(
            InvestigationCustodyEvent(
                id=str(uuid.uuid4()),
                case_id=case.id,
                evidence_id=evidence.id,
                actor_id=user.id,
                action="EVIDENCE_ANALYSIS_STARTED",
                evidence_sha256=evidence.sha256,
                metadata_json=json.dumps({"analyzer": "DSSS_DCT_DETECTOR_V1"}),
                created_at=now,
            )
        )
        AuditService.log_event(
            db=db,
            event_type="EVIDENCE_ANALYSIS_STARTED",
            user_id=user.id,
            document_id=case.document_id,
            metadata={"case_id": case.id, "evidence_id": evidence.id, "sha256": evidence.sha256},
        )
        db.commit()

        # Read evidence bytes
        try:
            evidence_bytes = EvidenceStorageService.read_evidence_bytes(evidence.storage_reference)
        except Exception as e:
            logger.error(f"Failed to read evidence bytes: {e}")
            case.status = "FAILED"
            evidence.processing_status = "FAILED"
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to read evidence artifact from protected storage.",
            )

        # Execute Phase 12 Signal Detection
        det_result: DetectionResult = FingerprintDetectionService.detect(
            evidence_bytes=evidence_bytes,
            filename=evidence.original_filename,
        )

        details: Dict[str, Any] = {
            "evidence_sha256": evidence.sha256,
            "embedding_profile": det_result.embedding_profile,
            "diagnostics": det_result.diagnostics,
        }

        # Handle detection outcomes
        if det_result.detection_status == "UNSUPPORTED_EVIDENCE":
            res = cls._record_result(
                db=db,
                case=case,
                evidence=evidence,
                detection_status="UNSUPPORTED_EVIDENCE_FORMAT",
                confidence=0.0,
                summary="The submitted evidence format cannot be processed by the signal-domain forensic analyzer.",
                limitations="Forensic analysis supports rasterized PDF pages, PNG, JPEG, and WebP images. Raw text or binary non-visual files cannot be analyzed in the frequency domain.",
                details=details,
                user=user,
            )
            case.status = "FAILED"
            evidence.processing_status = "FAILED"
            db.commit()
            return res

        if det_result.detection_status == "PROCESSING_ERROR":
            res = cls._record_result(
                db=db,
                case=case,
                evidence=evidence,
                detection_status="PROCESSING_ERROR",
                confidence=0.0,
                summary=f"Forensic signal extraction failed due to processing error: {det_result.diagnostics.get('error')}",
                limitations="Corrupted or malformed image headers prevent 2D-DCT coefficient decomposition.",
                details=details,
                user=user,
            )
            case.status = "FAILED"
            evidence.processing_status = "FAILED"
            db.commit()
            return res

        if det_result.detection_status != "FINGERPRINT_DETECTED" or not det_result.candidate_token:
            res = cls._record_result(
                db=db,
                case=case,
                evidence=evidence,
                detection_status="NO_DETECTABLE_FINGERPRINT",
                confidence=det_result.confidence_score,
                summary="No detectable forensic fingerprint was recovered from the submitted evidence.",
                limitations="Absence of a detectable fingerprint does not prove the document was never viewed or distributed. Severe optical downscaling, aggressive lossy recompression (JPEG Q < 60), heavy cropping, or re-typing destroys embedded high-frequency spread-spectrum signals.",
                details=details,
                user=user,
            )
            case.status = "COMPLETED"
            case.completed_at = datetime.now(timezone.utc)
            evidence.processing_status = "ANALYZED"
            db.commit()
            return res

        # Candidate token detected! Perform database lookup
        fp_rec = (
            db.query(ForensicFingerprint)
            .filter(ForensicFingerprint.fingerprint_token == det_result.candidate_token)
            .first()
        )

        if not fp_rec:
            # Token detected from PN correlation, but not registered in this system
            details["unregistered_token"] = det_result.candidate_token
            res = cls._record_result(
                db=db,
                case=case,
                evidence=evidence,
                detection_status="FINGERPRINT_DETECTED",
                confidence=det_result.confidence_score,
                summary=f"Forensic fingerprint signal detected with token '{det_result.candidate_token}', but no matching authorized session is recorded in this platform.",
                limitations="The detected token is not registered in the active database. The evidence may have originated from an external system or an expired ledger archive.",
                details=details,
                user=user,
            )
            case.status = "COMPLETED"
            case.completed_at = datetime.now(timezone.utc)
            evidence.processing_status = "ANALYZED"
            db.commit()
            return res

        # Correlate session metadata
        vs = fp_rec.viewer_session
        ds = fp_rec.decryption_session
        doc = fp_rec.document
        recipient = fp_rec.recipient_user

        details["correlation"] = {
            "fingerprint_id": fp_rec.id,
            "fingerprint_token": fp_rec.fingerprint_token,
            "fingerprint_commitment": fp_rec.fingerprint_commitment,
            "recipient_id": recipient.id,
            "recipient_username": recipient.username,
            "recipient_email": recipient.email,
            "recipient_department": recipient.department.name if recipient.department else None,
            "viewer_session_id": fp_rec.viewer_session_id,
            "decryption_session_id": fp_rec.decryption_session_id,
            "document_id": doc.id,
            "document_title": doc.title,
            "document_version_id": fp_rec.document_version_id,
            "device_id": vs.device_id if vs else None,
            "session_created_at": vs.created_at.isoformat() if vs else None,
        }

        # Cryptographic Provenance Verification (ML-DSA-65)
        prov_sig_status = "UNAVAILABLE"
        chain_ver_status = "UNAVAILABLE"
        ledger_ver_status = "UNAVAILABLE"
        prov_valid = False
        chain_valid = False

        prov_rec = (
            db.query(ProvenanceRecord)
            .filter(ProvenanceRecord.event_id == fp_rec.provenance_event_id)
            .first()
        )

        if prov_rec:
            # 1. ML-DSA-65 signature verification
            AuditService.log_event(
                db=db,
                event_type="PROVENANCE_VERIFICATION_REQUESTED",
                user_id=user.id,
                document_id=doc.id,
                metadata={"case_id": case.id, "event_id": prov_rec.event_id},
            )
            try:
                sig_res = ProvenanceVerificationService.verify_record(db, prov_rec)
                prov_valid = bool(sig_res.get("verified", False) and sig_res.get("signature_valid", False))
                prov_sig_status = "VALID" if prov_valid else "INVALID"
                details["provenance"] = {
                    "event_id": prov_rec.event_id,
                    "access_type": prov_rec.access_type,
                    "signature_algorithm": prov_rec.signature_algorithm,
                    "signature_valid": sig_res.get("signature_valid"),
                    "hash_valid": sig_res.get("hash_valid"),
                    "verified": prov_valid,
                    "reason": sig_res.get("reason"),
                }
            except Exception as e:
                logger.error(f"Provenance signature verification error: {e}")
                prov_sig_status = "INVALID"
                details["provenance_error"] = str(e)

            AuditService.log_event(
                db=db,
                event_type="PROVENANCE_VERIFICATION_COMPLETED",
                user_id=user.id,
                document_id=doc.id,
                metadata={"case_id": case.id, "event_id": prov_rec.event_id, "status": prov_sig_status},
            )

            # 2. Provenance Chain Verification
            try:
                chain_res = ProvenanceService.verify_chain(db=db, chain_id=prov_rec.chain_id, verifying_user=user)
                chain_valid = chain_res.chain_valid
                chain_ver_status = "CHAIN_VALID" if chain_valid else "CHAIN_INVALID"
                details["chain"] = {
                    "chain_id": prov_rec.chain_id,
                    "chain_valid": chain_valid,
                    "records_checked": chain_res.records_checked,
                    "failure_type": chain_res.failure_type,
                    "failure_detail": chain_res.failure_detail,
                }
            except Exception as e:
                logger.error(f"Provenance chain verification error: {e}")
                chain_ver_status = "CHAIN_INVALID"
                details["chain_error"] = str(e)

            # 3. Ledger Anchor Verification
            AuditService.log_event(
                db=db,
                event_type="LEDGER_VERIFICATION_REQUESTED",
                user_id=user.id,
                document_id=doc.id,
                metadata={"case_id": case.id, "event_id": prov_rec.event_id},
            )
            try:
                anchor_res = ProvenanceService.verify_ledger_anchor(db=db, event_id=prov_rec.event_id, verifying_user=user)
                ledger_ver_status = f"LEDGER_{anchor_res.status}" if not anchor_res.status.startswith("LEDGER_") else anchor_res.status
                details["ledger"] = {
                    "status": anchor_res.status,
                    "is_anchored": anchor_res.is_anchored,
                    "transaction_id": anchor_res.transaction_id,
                    "hash_matched": anchor_res.hash_matched,
                    "details": anchor_res.details,
                }
            except Exception as e:
                logger.error(f"Ledger anchor verification error: {e}")
                ledger_ver_status = "LEDGER_UNAVAILABLE"
                details["ledger_error"] = str(e)

            AuditService.log_event(
                db=db,
                event_type="LEDGER_VERIFICATION_COMPLETED",
                user_id=user.id,
                document_id=doc.id,
                metadata={"case_id": case.id, "event_id": prov_rec.event_id, "status": ledger_ver_status},
            )

        # Determine overall factual result state
        if not prov_valid:
            final_status = "FINGERPRINT_DETECTED_PROVENANCE_INVALID"
        elif not chain_valid:
            final_status = "FINGERPRINT_DETECTED_CHAIN_INVALID"
        elif ledger_ver_status == "LEDGER_MISMATCH":
            final_status = "FINGERPRINT_DETECTED_LEDGER_MISMATCH"
        else:
            final_status = "FINGERPRINT_DETECTED_PROVENANCE_VALID"

        dept_str = recipient.department.name if recipient.department else "Unassigned"
        summary_text = (
            f"An embedded forensic fingerprint was detected in the submitted evidence and cryptographically "
            f"associated with authorized viewing session '{fp_rec.viewer_session_id}' and decryption session "
            f"'{fp_rec.decryption_session_id}', issued to recipient '{recipient.username}' (Department: {dept_str}). "
            f"The underlying ML-DSA-65 post-quantum provenance signature was independently verified as {prov_sig_status}. "
            f"The provenance hash chain was verified as {chain_ver_status}, and ledger anchor status was recorded as {ledger_ver_status}."
        )

        limitations_text = (
            "LEGAL & FORENSIC BOUNDARY NOTICE:\n"
            "This finding establishes a mathematical association between the evidence and an authorized decryption session. "
            "It does NOT establish legal intent, culpability, or whether the recipient intentionally disclosed the document. "
            "A leak may occur through unauthorized physical photography, screen observation, or endpoint malware."
        )

        res = cls._record_result(
            db=db,
            case=case,
            evidence=evidence,
            detection_status=final_status,
            confidence=det_result.confidence_score,
            summary=summary_text,
            limitations=limitations_text,
            details=details,
            user=user,
            fingerprint_id=fp_rec.id,
            provenance_event_id=fp_rec.provenance_event_id,
            prov_sig_status=prov_sig_status,
            chain_status=chain_ver_status,
            ledger_status=ledger_ver_status,
        )

        case.status = "COMPLETED"
        case.completed_at = datetime.now(timezone.utc)
        evidence.processing_status = "ANALYZED"
        db.commit()
        return res

    @classmethod
    def _record_result(
        cls,
        db: Session,
        case: InvestigationCase,
        evidence: InvestigationEvidence,
        detection_status: str,
        confidence: float,
        summary: str,
        limitations: str,
        details: Dict[str, Any],
        user: User,
        fingerprint_id: Optional[str] = None,
        provenance_event_id: Optional[str] = None,
        prov_sig_status: Optional[str] = None,
        chain_status: Optional[str] = None,
        ledger_status: Optional[str] = None,
    ) -> InvestigationResultResponse:
        """Internal helper to persist investigation results, log custody events, and audit actions."""
        now = datetime.now(timezone.utc)
        result = InvestigationResult(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            detection_status=detection_status,
            fingerprint_id=fingerprint_id,
            provenance_event_id=provenance_event_id,
            provenance_signature_status=prov_sig_status,
            chain_verification_status=chain_status,
            ledger_verification_status=ledger_status,
            confidence_score=confidence,
            analyzed_at=now,
            analyzer_version="FORENSIC-V12",
            result_summary=summary,
            limitations=limitations,
            details_json=json.dumps(details),
        )
        db.add(result)

        action_name = "EVIDENCE_ANALYSIS_COMPLETED" if "ERROR" not in detection_status and "FAILED" not in detection_status else "EVIDENCE_ANALYSIS_FAILED"
        custody_event = InvestigationCustodyEvent(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            actor_id=user.id,
            action=action_name,
            evidence_sha256=evidence.sha256,
            metadata_json=json.dumps({
                "detection_status": detection_status,
                "confidence": confidence,
                "fingerprint_id": fingerprint_id,
                "provenance_event_id": provenance_event_id,
            }),
            created_at=now,
        )
        db.add(custody_event)
        db.commit()
        db.refresh(result)

        AuditService.log_event(
            db=db,
            event_type=action_name,
            user_id=user.id,
            document_id=case.document_id,
            metadata={
                "case_id": case.id,
                "evidence_id": evidence.id,
                "detection_status": detection_status,
                "fingerprint_id": fingerprint_id,
                "provenance_event_id": provenance_event_id,
            },
        )

        return InvestigationResultResponse(
            id=result.id,
            case_id=result.case_id,
            evidence_id=result.evidence_id,
            detection_status=result.detection_status,
            fingerprint_id=result.fingerprint_id,
            provenance_event_id=result.provenance_event_id,
            provenance_signature_status=result.provenance_signature_status,
            chain_verification_status=result.chain_verification_status,
            ledger_verification_status=result.ledger_verification_status,
            confidence_score=result.confidence_score,
            analyzed_at=result.analyzed_at,
            analyzer_version=result.analyzer_version,
            result_summary=result.result_summary,
            limitations=result.limitations,
            details=details,
        )

    @classmethod
    def get_case_detail(cls, db: Session, case_id: str, user: User) -> InvestigationCaseDetailResponse:
        """Assembles comprehensive case details with evidence items, chain of custody, results, and timeline."""
        cls._check_investigator_role(user)
        case = cls.get_case(db, case_id, user)

        evidence_items = [InvestigationEvidenceResponse.model_validate(e) for e in case.evidence_items]
        
        custody_list: List[CustodyEventResponse] = []
        for c in case.custody_events:
            meta = {}
            if c.metadata_json:
                try:
                    meta = json.loads(c.metadata_json)
                except Exception:
                    pass
            custody_list.append(
                CustodyEventResponse(
                    id=c.id,
                    case_id=c.case_id,
                    evidence_id=c.evidence_id,
                    actor_id=c.actor_id,
                    action=c.action,
                    evidence_sha256=c.evidence_sha256,
                    metadata=meta,
                    created_at=c.created_at,
                )
            )

        results_list: List[InvestigationResultResponse] = []
        for r in case.results:
            d = {}
            if r.details_json:
                try:
                    d = json.loads(r.details_json)
                except Exception:
                    pass
            results_list.append(
                InvestigationResultResponse(
                    id=r.id,
                    case_id=r.case_id,
                    evidence_id=r.evidence_id,
                    detection_status=r.detection_status,
                    fingerprint_id=r.fingerprint_id,
                    provenance_event_id=r.provenance_event_id,
                    provenance_signature_status=r.provenance_signature_status,
                    chain_verification_status=r.chain_verification_status,
                    ledger_verification_status=r.ledger_verification_status,
                    confidence_score=r.confidence_score,
                    analyzed_at=r.analyzed_at,
                    analyzer_version=r.analyzer_version,
                    result_summary=r.result_summary,
                    limitations=r.limitations,
                    details=d,
                )
            )

        timeline = cls._build_factual_timeline(db=db, case=case)

        case_resp = InvestigationCaseResponse(
            id=case.id,
            case_reference=case.case_reference,
            title=case.title,
            description=case.description,
            created_by=case.created_by,
            document_id=case.document_id,
            document_version_id=case.document_version_id,
            evidence_filename=case.evidence_filename,
            evidence_sha256=case.evidence_sha256,
            evidence_size=case.evidence_size,
            evidence_mime_type=case.evidence_mime_type,
            status=case.status,
            created_at=case.created_at,
            updated_at=case.updated_at,
            completed_at=case.completed_at,
            evidence_count=len(evidence_items),
            results_count=len(results_list),
        )

        return InvestigationCaseDetailResponse(
            case=case_resp,
            evidence_items=evidence_items,
            custody_chain=custody_list,
            results=results_list,
            timeline=timeline,
        )

    @classmethod
    def _build_factual_timeline(cls, db: Session, case: InvestigationCase) -> List[TimelineEvent]:
        """Constructs an un-fabricated chronological timeline strictly from real database records."""
        events: List[TimelineEvent] = []

        # 1. Document Upload / Genesis Event
        if case.document_id:
            doc = db.query(Document).filter(Document.id == case.document_id).first()
            if doc:
                events.append(
                    TimelineEvent(
                        event_name="DOCUMENT_UPLOADED",
                        timestamp=doc.created_at.isoformat(),
                        actor_or_source=doc.owner.username if doc.owner else "OWNER",
                        description=f"Encrypted document '{doc.title}' uploaded (Classification: {doc.classification.value if hasattr(doc.classification, 'value') else doc.classification}).",
                        verification_status="ENCRYPTED_AES256GCM",
                    )
                )

        # 2. Case Created
        events.append(
            TimelineEvent(
                event_name="INVESTIGATION_CASE_OPENED",
                timestamp=case.created_at.isoformat(),
                actor_or_source=case.creator.username if case.creator else case.created_by,
                description=f"Investigation case {case.case_reference} created with title '{case.title}'.",
                verification_status="CASE_OPENED",
            )
        )

        # 3. Evidence Uploaded
        for ev in case.evidence_items:
            events.append(
                TimelineEvent(
                    event_name="EVIDENCE_SUBMITTED",
                    timestamp=ev.uploaded_at.isoformat(),
                    actor_or_source=ev.uploader.username if ev.uploader else ev.uploaded_by,
                    description=f"Evidence artifact '{ev.original_filename}' deposited (SHA-256: {ev.sha256[:16]}...).",
                    verification_status="HASH_VERIFIED",
                )
            )

        # 4. Analysis Results & Provenance Correlation
        for res in case.results:
            details = {}
            if res.details_json:
                try:
                    details = json.loads(res.details_json)
                except Exception:
                    pass

            correlation = details.get("correlation", {})
            if correlation:
                # Add viewer session event if known
                session_time = correlation.get("session_created_at")
                if session_time:
                    events.append(
                        TimelineEvent(
                            event_name="AUTHORIZED_VIEWER_SESSION",
                            timestamp=session_time,
                            actor_or_source=correlation.get("recipient_username", "RECIPIENT"),
                            description=f"Viewer session '{correlation.get('viewer_session_id')}' initiated; recipient-specific fingerprint embedded.",
                            verification_status="WATERMARK_EMBEDDED",
                        )
                    )

            events.append(
                TimelineEvent(
                    event_name="FORENSIC_ANALYSIS_COMPLETED",
                    timestamp=res.analyzed_at.isoformat(),
                    actor_or_source="DSSS-DCT-DETECTOR",
                    description=f"Forensic detection status: {res.detection_status} (Confidence: {res.confidence_score:.2f}).",
                    verification_status=res.detection_status,
                )
            )

            if res.provenance_signature_status:
                events.append(
                    TimelineEvent(
                        event_name="PROVENANCE_SIGNATURE_VERIFIED",
                        timestamp=res.analyzed_at.isoformat(),
                        actor_or_source="ML-DSA-65-VALIDATOR",
                        description=f"ML-DSA-65 post-quantum digital signature on provenance record verified as {res.provenance_signature_status}.",
                        verification_status=res.provenance_signature_status,
                    )
                )

            if res.chain_verification_status:
                events.append(
                    TimelineEvent(
                        event_name="PROVENANCE_CHAIN_VERIFIED",
                        timestamp=res.analyzed_at.isoformat(),
                        actor_or_source="HASH-CHAIN-VALIDATOR",
                        description=f"Provenance hash chain continuity and links verified as {res.chain_verification_status}.",
                        verification_status=res.chain_verification_status,
                    )
                )

            if res.ledger_verification_status:
                events.append(
                    TimelineEvent(
                        event_name="LEDGER_ANCHOR_VERIFIED",
                        timestamp=res.analyzed_at.isoformat(),
                        actor_or_source="LEDGER-ADAPTER",
                        description=f"Ledger anchor transaction and chain hash verified as {res.ledger_verification_status}.",
                        verification_status=res.ledger_verification_status,
                    )
                )

        # Sort chronologically by ISO timestamp
        events.sort(key=lambda e: e.timestamp)
        return events

    @classmethod
    def generate_case_report(cls, db: Session, case_id: str, user: User) -> InvestigationReportResponse:
        """Generates exportable, cryptographically hashed investigation report."""
        cls._check_investigator_role(user)
        detail = cls.get_case_detail(db, case_id, user)
        case = cls.get_case(db, case_id, user)

        if not detail.evidence_items:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot generate report: No evidence has been uploaded for this case.",
            )

        if not detail.results:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot generate report: Forensic analysis has not been executed yet.",
            )

        evidence = case.evidence_items[-1]
        result = case.results[-1]

        report = InvestigationReportGenerator.generate_report(
            case=case,
            evidence=evidence,
            result=result,
            timeline=detail.timeline,
            generated_by_user_id=user.id,
        )

        # Custody event
        db.add(
            InvestigationCustodyEvent(
                id=str(uuid.uuid4()),
                case_id=case.id,
                evidence_id=evidence.id,
                actor_id=user.id,
                action="EVIDENCE_EXPORTED",
                evidence_sha256=evidence.sha256,
                metadata_json=json.dumps({"report_id": report.report_id, "report_sha256": report.report_sha256}),
                created_at=datetime.now(timezone.utc),
            )
        )
        AuditService.log_event(
            db=db,
            event_type="INVESTIGATION_REPORT_GENERATED",
            user_id=user.id,
            document_id=case.document_id,
            metadata={
                "case_id": case.id,
                "report_id": report.report_id,
                "report_sha256": report.report_sha256,
            },
        )
        db.commit()

        return report
