import io
from typing import Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from app.models.role import UserRole
from app.security.permissions import get_current_user, require_roles
from app.forensic.service import ForensicService
from app.forensic.evaluator import ForensicEvaluationUtility
from app.forensic.schemas import (
    ForensicFingerprintResponse,
    ForensicDetectionResponse,
    ForensicEvaluationReport,
)

router = APIRouter()


@router.post(
    "/forensics/detect",
    response_model=ForensicDetectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Detect forensic fingerprint from evidence and correlate with provenance records",
)
async def detect_fingerprint_from_evidence(
    file: UploadFile = File(..., description="Leaked document evidence (PDF, image, photograph, or screenshot)"),
    expected_document_id: Optional[str] = Form(None, description="Optional document ID if known during investigation"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    """Forensic investigation API:
    Analyzes submitted evidence for invisible DSSS-DCT forensic fingerprints,
    correlates detected fingerprints with authorized viewing sessions,
    and cryptographically verifies the associated ML-DSA-65 provenance and ledger anchor.
    
    Access Control: Restricted to ADMIN and AUDITOR roles.
    """
    evidence_bytes = await file.read()
    if not evidence_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Evidence file cannot be empty.",
        )

    return ForensicService.investigate_evidence(
        db=db,
        evidence_bytes=evidence_bytes,
        filename=file.filename or "evidence.bin",
        investigating_user=current_user,
        expected_document_id=expected_document_id,
    )


@router.get(
    "/forensics/fingerprints/{fingerprint_id}",
    response_model=ForensicFingerprintResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve forensic fingerprint metadata by ID",
)
def get_fingerprint_metadata(
    fingerprint_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    """Retrieves recorded forensic fingerprint metadata for an investigation."""
    fp = ForensicService.get_fingerprint_by_id(db=db, fingerprint_id=fingerprint_id, requesting_user=current_user)
    return ForensicFingerprintResponse.model_validate(fp)


@router.get(
    "/forensics/sessions/{viewer_session_id}",
    response_model=ForensicFingerprintResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve forensic fingerprint for a viewer session",
)
def get_session_fingerprint(
    viewer_session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    """Retrieves the forensic fingerprint generated for a specific viewing session."""
    fp = ForensicService.get_fingerprint_for_viewer_session(
        db=db, viewer_session_id=viewer_session_id, requesting_user=current_user
    )
    return ForensicFingerprintResponse.model_validate(fp)


@router.post(
    "/forensics/evaluate",
    response_model=ForensicEvaluationReport,
    status_code=status.HTTP_200_OK,
    summary="Execute laboratory benchmark measuring real transformation robustness (Admin only)",
)
def evaluate_forensic_robustness(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN])),
):
    """Executes a real empirical robustness evaluation across multiple transformations
    (JPEG compression, resizing, contrast, brightness, Gaussian noise) and returns measured statistics.
    
    Access Control: Restricted to ADMIN role.
    """
    return ForensicEvaluationUtility.run_benchmark()
