import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List

from app.models.investigation import InvestigationCase, InvestigationEvidence, InvestigationResult
from app.investigation.schemas import InvestigationReportResponse, TimelineEvent


class InvestigationReportGenerator:
    """Generates immutable, factually disciplined forensic investigation reports."""

    REPORT_VERSION = "SDP-FORENSIC-REPORT-V1"
    LEGAL_LIMITATIONS_DISCLAIMER = (
        "LEGAL & FORENSIC LIMITATIONS DISCLAIMER:\n"
        "1. Association vs. Intent: The forensic fingerprint and cryptographic provenance records establish "
        "a cryptographic association between the submitted evidence and a specific authorized viewing/decryption session. "
        "This platform does not determine intent, motive, or culpability.\n"
        "2. Physical Capture Boundaries: Screen photographs or printed analog captures may introduce optical distortion, "
        "halftoning, or partial occlusion. Detection confidence is mathematically derived from DSSS-DCT cross-correlation.\n"
        "3. Source Integrity: The authoritative encrypted document remains immutable in secure storage; watermarking is "
        "performed solely in volatile memory during authorized viewer rendering.\n"
        "4. Factual Finding: All cryptographic signatures (ML-DSA-65) and ledger hash chains are verified without "
        "manual overrides or simulated proofs."
    )

    @classmethod
    def generate_report(
        cls,
        case: InvestigationCase,
        evidence: InvestigationEvidence,
        result: InvestigationResult,
        timeline: List[TimelineEvent],
        generated_by_user_id: str,
    ) -> InvestigationReportResponse:
        """Constructs a deterministic, exportable investigation report and calculates its SHA-256 integrity hash."""
        now = datetime.now(timezone.utc)
        report_id = f"REP-{uuid.uuid4().hex[:12].upper()}"

        details: Dict[str, Any] = {}
        if result.details_json:
            try:
                details = json.loads(result.details_json)
            except Exception:
                details = {}

        evidence_meta = {
            "evidence_id": evidence.id,
            "original_filename": evidence.original_filename,
            "mime_type": evidence.mime_type,
            "size_bytes": evidence.size_bytes,
            "uploaded_at": evidence.uploaded_at.isoformat(),
            "uploaded_by_user_id": evidence.uploaded_by,
            "evidence_version": evidence.evidence_version,
        }

        prov_info = details.get("provenance", {})
        chain_info = details.get("chain", {})
        ledger_info = details.get("ledger", {})

        payload_to_hash = {
            "report_id": report_id,
            "report_version": cls.REPORT_VERSION,
            "case_reference": case.case_reference,
            "evidence_sha256": evidence.sha256,
            "detection_status": result.detection_status,
            "confidence_score": result.confidence_score,
            "provenance_signature_status": result.provenance_signature_status,
            "chain_verification_status": result.chain_verification_status,
            "ledger_verification_status": result.ledger_verification_status,
            "analyzed_at": result.analyzed_at.isoformat(),
            "generated_at": now.isoformat(),
        }
        canonical_bytes = json.dumps(payload_to_hash, sort_keys=True).encode("utf-8")
        report_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

        return InvestigationReportResponse(
            report_id=report_id,
            report_version=cls.REPORT_VERSION,
            case_reference=case.case_reference,
            case_title=case.title,
            generated_at=now,
            generated_by_user_id=generated_by_user_id,
            evidence_metadata=evidence_meta,
            evidence_sha256=evidence.sha256,
            detection_status=result.detection_status,
            provenance_verification={
                "status": result.provenance_signature_status or "UNAVAILABLE",
                "event_id": result.provenance_event_id,
                "details": prov_info,
            },
            chain_verification={
                "status": result.chain_verification_status or "UNAVAILABLE",
                "details": chain_info,
            },
            ledger_verification={
                "status": result.ledger_verification_status or "UNAVAILABLE",
                "details": ledger_info,
            },
            factual_findings=result.result_summary,
            timeline=timeline,
            limitations_disclaimer=cls.LEGAL_LIMITATIONS_DISCLAIMER,
            report_sha256=report_sha256,
        )
