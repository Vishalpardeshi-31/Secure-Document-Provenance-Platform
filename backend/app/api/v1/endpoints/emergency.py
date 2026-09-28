import base64
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Header, Body
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from app.models.emergency_access import EmergencyAccessRequest
from app.schemas.emergency import (
    EmergencyAccessCreateRequest,
    EmergencyDecisionRequest,
    EmergencyAccessResponse,
)
from app.schemas.decryption import DecryptionResultResponse
from app.models.device import Device
from app.services.emergency_service import EmergencyAccessService
from app.security.permissions import get_current_user, require_step_up_assurance

router = APIRouter()


def _to_emergency_response(req: EmergencyAccessRequest) -> EmergencyAccessResponse:
    return EmergencyAccessResponse(
        id=req.id,
        document_id=req.document_id,
        requester_user_id=req.requester_user_id,
        requester_role=req.requester_role,
        reason=req.reason,
        status=req.status,
        created_at=req.created_at,
        expires_at=req.expires_at,
        approved_at=req.approved_at,
        completed_at=req.completed_at,
        approver_user_id=req.approver_user_id,
        rejection_reason=req.rejection_reason,
    )


@router.post(
    "/documents/{document_id}/emergency-requests",
    response_model=EmergencyAccessResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate an emergency break-glass access request",
)
def create_emergency_access_request(
    document_id: str,
    request_data: EmergencyAccessCreateRequest = Body(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_step_up_assurance()),
):
    """Initiates an emergency break-glass access request requiring explicit reason and authorization."""
    try:
        req = EmergencyAccessService.request_emergency_access(
            db=db,
            document_id=document_id,
            user=current_user,
            reason=request_data.reason,
            requested_duration_minutes=request_data.requested_duration_minutes,
        )
        return _to_emergency_response(req)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.get(
    "/documents/{document_id}/emergency-requests",
    response_model=List[EmergencyAccessResponse],
    summary="List emergency break-glass requests for a document",
)
def list_document_emergency_requests(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists emergency requests for the specified document."""
    requests = EmergencyAccessService.list_requests(db=db, user=current_user, document_id=document_id)
    return [_to_emergency_response(r) for r in requests]


@router.get(
    "/emergency-requests/{request_id}",
    response_model=EmergencyAccessResponse,
    summary="Get status of an emergency access request",
)
def get_emergency_access_request(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves an emergency access request."""
    try:
        req = EmergencyAccessService.get_emergency_request(db=db, request_id=request_id, user=current_user)
        return _to_emergency_response(req)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))


@router.post(
    "/emergency-requests/{request_id}/approve",
    response_model=EmergencyAccessResponse,
    summary="Independently authorize an emergency break-glass access request",
)
def approve_emergency_access_request(
    request_id: str,
    decision_data: Optional[EmergencyDecisionRequest] = Body(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_step_up_assurance()),
):
    """Authorizes an emergency break-glass request. Enforces independent emergency approver."""
    try:
        reason = decision_data.reason if decision_data else None
        req = EmergencyAccessService.approve_emergency_access(
            db=db,
            request_id=request_id,
            approver=current_user,
            reason=reason,
        )
        return _to_emergency_response(req)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.post(
    "/emergency-requests/{request_id}/reject",
    response_model=EmergencyAccessResponse,
    summary="Reject an emergency break-glass access request",
)
def reject_emergency_access_request(
    request_id: str,
    decision_data: EmergencyDecisionRequest = Body(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Rejects an emergency break-glass request. Reason is required."""
    try:
        req = EmergencyAccessService.reject_emergency_access(
            db=db,
            request_id=request_id,
            approver=current_user,
            reason=decision_data.reason,
        )
        return _to_emergency_response(req)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.post(
    "/documents/{document_id}/emergency-decrypt",
    response_model=DecryptionResultResponse,
    summary="Execute time-limited emergency break-glass document decryption",
)
def execute_emergency_decryption(
    document_id: str,
    emergency_request_id: Optional[str] = Body(None, embed=True),
    x_device_id: Optional[str] = Header(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_step_up_assurance()),
):
    """Executes authorized emergency document decryption under explicit server-controlled key access."""
    if x_device_id:
        dev = db.query(Device).filter(Device.id == x_device_id).first()
        if not dev or dev.status == "REVOKED" or dev.registration_status == "REVOKED" or dev.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Emergency decryption denied: device is revoked or unauthorized.",
            )

    try:
        session, plaintext = EmergencyAccessService.execute_emergency_decryption(
            db=db,
            document_id=document_id,
            user=current_user,
            emergency_request_id=emergency_request_id,
            device_id=x_device_id,
        )
        doc = session.document
        return DecryptionResultResponse(
            session_id=session.id,
            document_id=doc.id,
            status=session.status,
            original_filename=doc.original_filename,
            mime_type=doc.mime_type,
            original_size_bytes=len(plaintext),
            plaintext_sha256=doc.plaintext_sha256,
            plaintext_base64=base64.b64encode(plaintext).decode("ascii"),
            completed_at=session.completed_at or datetime.now(timezone.utc),
        )
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
