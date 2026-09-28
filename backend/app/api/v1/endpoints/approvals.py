from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Header, Body
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from app.models.approval import ApprovalRequest
from app.schemas.approval import (
    ApprovalRequestResponse,
    ApprovalRecordResponse,
    ApprovalDecisionRequest,
)
from app.services.approval_service import ApprovalService
from app.security.permissions import get_current_user, require_step_up_assurance

router = APIRouter()


def _to_approval_response(req: ApprovalRequest) -> ApprovalRequestResponse:
    records = req.records or []
    approved_count = len([r for r in records if r.decision == "APPROVED"])
    return ApprovalRequestResponse(
        id=req.id,
        document_id=req.document_id,
        requesting_user_id=req.requesting_user_id,
        decryption_session_id=req.decryption_session_id,
        policy_id=req.policy_id,
        policy_version=req.policy_version,
        required_approvals=req.required_approvals,
        current_approvals=approved_count,
        status=req.status,
        created_at=req.created_at,
        expires_at=req.expires_at,
        completed_at=req.completed_at,
        records=[
            ApprovalRecordResponse(
                id=rec.id,
                approval_request_id=rec.approval_request_id,
                approver_user_id=rec.approver_user_id,
                approver_role=rec.approver_role,
                decision=rec.decision,
                reason=rec.reason,
                created_at=rec.created_at,
            )
            for rec in records
        ],
    )


@router.post(
    "/documents/{document_id}/decryption-requests",
    response_model=ApprovalRequestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a multi-party approval request for document decryption",
)
def create_decryption_approval_request(
    document_id: str,
    x_device_id: Optional[str] = Header(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Initiates a multi-party approval request when document policy requires multiple approvers."""
    try:
        req = ApprovalService.create_request(
            db=db,
            document_id=document_id,
            user=current_user,
            device_id=x_device_id,
        )
        return _to_approval_response(req)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.get(
    "/documents/{document_id}/decryption-requests",
    response_model=List[ApprovalRequestResponse],
    summary="List approval requests for a specific document",
)
def list_document_approval_requests(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists approval requests associated with the document."""
    requests = ApprovalService.list_requests_for_user(db=db, user=current_user, document_id=document_id)
    return [_to_approval_response(r) for r in requests]


@router.get(
    "/decryption-requests/pending",
    response_model=List[ApprovalRequestResponse],
    summary="List pending approval requests",
)
def list_pending_approval_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists currently pending approval requests."""
    requests = ApprovalService.list_requests_for_user(db=db, user=current_user, status="PENDING")
    return [_to_approval_response(r) for r in requests]


@router.get(
    "/decryption-requests/{request_id}",
    response_model=ApprovalRequestResponse,
    summary="Get details and current status of an approval request",
)
def get_approval_request_status(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves current status, threshold progress, and decision records for an approval request."""
    try:
        req = ApprovalService.get_request(db=db, request_id=request_id, user=current_user)
        return _to_approval_response(req)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))


@router.post(
    "/decryption-requests/{request_id}/approve",
    response_model=ApprovalRequestResponse,
    summary="Record an independent approval decision",
)
def approve_decryption_request(
    request_id: str,
    decision_data: Optional[ApprovalDecisionRequest] = Body(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_step_up_assurance()),
):
    """Records an approval decision. Enforces approver independence, role eligibility, and thresholds."""
    try:
        reason = decision_data.reason if decision_data else None
        req = ApprovalService.approve_request(
            db=db,
            request_id=request_id,
            approver=current_user,
            reason=reason,
        )
        return _to_approval_response(req)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.post(
    "/decryption-requests/{request_id}/reject",
    response_model=ApprovalRequestResponse,
    summary="Record a rejection decision",
)
def reject_decryption_request(
    request_id: str,
    decision_data: ApprovalDecisionRequest = Body(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Records a rejection decision. Requires an explicit reason."""
    try:
        req = ApprovalService.reject_request(
            db=db,
            request_id=request_id,
            approver=current_user,
            reason=decision_data.reason,
        )
        return _to_approval_response(req)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.post(
    "/decryption-requests/{request_id}/cancel",
    response_model=ApprovalRequestResponse,
    summary="Cancel a pending approval request",
)
def cancel_decryption_request(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Cancels a pending approval request. Only the requester or administrator can cancel."""
    try:
        req = ApprovalService.cancel_request(db=db, request_id=request_id, user=current_user)
        return _to_approval_response(req)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
