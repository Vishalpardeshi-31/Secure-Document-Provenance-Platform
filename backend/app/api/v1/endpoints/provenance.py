"""API endpoints for cryptographic document provenance, hash chain, and ledger verification."""
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import User
from app.security.permissions import get_current_user, require_role
from app.models.role import UserRole
from app.provenance.service import ProvenanceService
from app.provenance.schemas import (
    ProvenanceRecordResponse,
    ProvenanceVerificationResponse,
    ProvenanceSigningKeyResponse,
    ProvenanceChainHeadResponse,
    ProvenanceChainVerificationResponse,
    LedgerAnchorVerificationResponse,
    LedgerOutboxProcessResponse,
)

router = APIRouter()


@router.get(
    "/documents/{document_id}/provenance",
    response_model=List[ProvenanceRecordResponse],
    status_code=status.HTTP_200_OK,
    summary="Get cryptographic provenance history for a document",
)
def get_document_provenance(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves all signed cryptographic provenance records for a given document."""
    return ProvenanceService.get_provenance_for_document(
        db=db,
        document_id=document_id,
        requesting_user=current_user,
    )


@router.get(
    "/provenance/chain/head",
    response_model=ProvenanceChainHeadResponse,
    status_code=status.HTTP_200_OK,
    summary="Get the verifiable tip of the provenance hash chain",
)
def get_chain_head(
    chain_id: str = Query("PLATFORM-PROVENANCE-CHAIN", description="Identifier of the provenance chain"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves the latest sequence number, tip chain hash, and genesis hash of the specified chain."""
    return ProvenanceService.get_chain_head(db=db, chain_id=chain_id, requesting_user=current_user)


@router.get(
    "/provenance/chain/records",
    response_model=List[ProvenanceRecordResponse],
    status_code=status.HTTP_200_OK,
    summary="List ordered records from the provenance hash chain",
)
def list_chain_records(
    chain_id: str = Query("PLATFORM-PROVENANCE-CHAIN", description="Identifier of the provenance chain"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists records in strict sequence order from the provenance chain."""
    return ProvenanceService.list_chain_records(
        db=db, chain_id=chain_id, requesting_user=current_user, skip=skip, limit=limit
    )


@router.post(
    "/provenance/chain/verify",
    response_model=ProvenanceChainVerificationResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute full cryptographic audit verification of the provenance hash chain",
)
def verify_full_chain(
    chain_id: str = Query("PLATFORM-PROVENANCE-CHAIN", description="Identifier of the provenance chain"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Audits the complete provenance hash chain from genesis to head:
    
    1. Validates Genesis at sequence 0.
    2. Validates strict sequence continuity (SEQUENCE_GAP detection).
    3. Validates previous hash chaining (PREVIOUS_HASH_MISMATCH detection).
    4. Recomputes and compares SHA-256 chain hashes (CHAIN_HASH_MISMATCH detection).
    5. Cryptographically verifies ML-DSA-65 signatures on all operational records.
    6. Verifies ledger anchor references against the configured ledger adapter.
    """
    return ProvenanceService.verify_chain(db=db, chain_id=chain_id, verifying_user=current_user)


@router.get(
    "/provenance/{event_id}",
    response_model=ProvenanceRecordResponse,
    status_code=status.HTTP_200_OK,
    summary="Get detailed cryptographic provenance record by event ID",
)
def get_provenance_by_event_id(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves an individual cryptographic provenance record by its unique event ID."""
    return ProvenanceService.get_provenance_by_event_id(
        db=db,
        event_id=event_id,
        requesting_user=current_user,
    )


@router.post(
    "/provenance/{event_id}/verify",
    response_model=ProvenanceVerificationResponse,
    status_code=status.HTTP_200_OK,
    summary="Cryptographically verify a provenance record with ML-DSA-65",
)
def verify_provenance_record(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Cryptographically verifies an individual provenance record's canonical digest and ML-DSA-65 signature."""
    return ProvenanceService.verify_provenance(
        db=db,
        event_id=event_id,
        verifying_user=current_user,
    )


@router.get(
    "/provenance/{event_id}/ledger-anchor",
    response_model=LedgerAnchorVerificationResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify record anchor against the permissioned ledger",
)
def verify_record_ledger_anchor(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Checks whether the event is anchored to the permissioned ledger and verifies chain hash integrity."""
    return ProvenanceService.verify_ledger_anchor(db=db, event_id=event_id, verifying_user=current_user)


@router.post(
    "/provenance/ledger/outbox/process",
    response_model=LedgerOutboxProcessResponse,
    status_code=status.HTTP_200_OK,
    summary="Process pending ledger outbox items (Admin only)",
)
def process_ledger_outbox(
    max_items: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Processes pending outbox items and submits them to the configured ledger adapter."""
    return ProvenanceService.process_ledger_outbox(db=db, admin_user=current_user, max_items=max_items)


@router.post(
    "/provenance/keys/rotate",
    response_model=ProvenanceSigningKeyResponse,
    status_code=status.HTTP_200_OK,
    summary="Rotate ML-DSA-65 provenance signing key (Admin only)",
)
def rotate_provenance_signing_key(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Administratively rotates the active ML-DSA-65 provenance signing key."""
    return ProvenanceService.rotate_signing_key(db=db, admin_user=current_user)


@router.get(
    "/provenance/keys",
    response_model=List[ProvenanceSigningKeyResponse],
    status_code=status.HTTP_200_OK,
    summary="List provenance public signing keys (Privileged only)",
)
def list_provenance_signing_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists historical and active provenance public keys."""
    return ProvenanceService.list_signing_keys(db=db, requesting_user=current_user)
