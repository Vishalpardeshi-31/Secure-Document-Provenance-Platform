import io
from typing import List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from app.models.role import UserRole
from app.security.permissions import require_roles
from app.investigation.service import InvestigationService
from app.investigation.schemas import (
    InvestigationCaseCreateRequest,
    InvestigationCaseResponse,
    InvestigationCaseDetailResponse,
    InvestigationEvidenceResponse,
    InvestigationResultResponse,
    InvestigationReportResponse,
)

router = APIRouter()


@router.post(
    "/investigations",
    response_model=InvestigationCaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new forensic leak investigation case",
)
def create_investigation_case(
    request: InvestigationCaseCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    """Initializes a new formal investigation case container.
    
    Access Control: Restricted to ADMIN and AUDITOR roles.
    """
    return InvestigationService.create_case(db=db, request=request, user=current_user)


@router.get(
    "/investigations",
    response_model=List[InvestigationCaseResponse],
    status_code=status.HTTP_200_OK,
    summary="List investigation cases",
)
def list_investigation_cases(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    """Retrieves paginated investigation cases for authorized investigators."""
    return InvestigationService.list_cases(db=db, user=current_user, limit=limit, offset=offset)


@router.get(
    "/investigations/{case_id}",
    response_model=InvestigationCaseDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve detailed investigation case with evidence, chain of custody, and verified timeline",
)
def get_investigation_case_detail(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    """Returns comprehensive case details, uploaded evidence items, immutable chain of custody events,
    verified results, and factual chronology.
    """
    return InvestigationService.get_case_detail(db=db, case_id=case_id, user=current_user)


@router.post(
    "/investigations/{case_id}/evidence",
    response_model=InvestigationEvidenceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Deposit suspected leak evidence artifact for an investigation case",
)
async def upload_case_evidence(
    case_id: str,
    file: UploadFile = File(..., description="Suspected leaked document or photograph"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    """Deposits an evidence artifact into isolated evidence storage, verifies its SHA-256 hash,
    and logs immutable chain of custody events.
    
    Access Control: Restricted to ADMIN and AUDITOR roles.
    """
    content = await file.read()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Evidence file cannot be empty.",
        )

    return InvestigationService.upload_evidence(
        db=db,
        case_id=case_id,
        evidence_bytes=content,
        filename=file.filename or "evidence.bin",
        mime_type=file.content_type or "application/octet-stream",
        user=current_user,
    )


@router.get(
    "/investigations/{case_id}/evidence",
    response_model=List[InvestigationEvidenceResponse],
    status_code=status.HTTP_200_OK,
    summary="List all deposited evidence artifacts for a case",
)
def list_case_evidence(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    """Lists evidence items and their cryptographic hashes for an investigation case."""
    case = InvestigationService.get_case(db=db, case_id=case_id, user=current_user)
    return [InvestigationEvidenceResponse.model_validate(e) for e in case.evidence_items]


@router.post(
    "/investigations/{case_id}/analyze",
    response_model=InvestigationResultResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute forensic analysis and end-to-end cryptographic verification on case evidence",
)
def analyze_case_evidence(
    case_id: str,
    evidence_id: Optional[str] = Query(None, description="Optional specific evidence ID; defaults to latest"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    """Executes the complete forensic signal analysis on deposited evidence:
    1. 2D-DCT spread-spectrum signal detection.
    2. Candidate token lookup & viewing session correlation.
    3. Real ML-DSA-65 post-quantum digital signature re-verification.
    4. Tamper-evident provenance hash chain continuity verification.
    5. Append-only ledger anchor transaction verification.
    """
    return InvestigationService.analyze_evidence(
        db=db,
        case_id=case_id,
        evidence_id=evidence_id,
        user=current_user,
    )


@router.get(
    "/investigations/{case_id}/report",
    response_model=InvestigationReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate and export formal investigation report with cryptographic proofs",
)
def export_investigation_report(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    """Generates an immutable, cryptographically hashed investigation report containing
    evidence metadata, factual findings, verified provenance details, and legal boundary disclosures.
    """
    return InvestigationService.generate_case_report(db=db, case_id=case_id, user=current_user)
