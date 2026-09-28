from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status, Response
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from app.models.device import Device
from app.security.permissions import get_current_user, require_step_up_assurance
from app.schemas.viewer import (
    ViewerSessionCreateRequest,
    ViewerSessionResponse,
    ViewerHeartbeatResponse,
    ViewerCloseResponse,
)
from app.services.viewer_session_service import ViewerSessionService

router = APIRouter()


def _to_viewer_response(session) -> ViewerSessionResponse:
    now = datetime.now(timezone.utc)
    exp = session.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    remaining = max(0, int((exp - now).total_seconds()))
    is_expired = remaining == 0 or session.status == "EXPIRED"

    doc = session.document
    return ViewerSessionResponse(
        viewer_session_id=session.id,
        decryption_session_id=session.decryption_session_id,
        provenance_event_id=session.provenance_event_id,
        document_id=session.document_id,
        document_title=doc.title if doc else None,
        original_filename=doc.original_filename if doc else "document",
        mime_type=doc.mime_type or "application/octet-stream" if doc else "application/octet-stream",
        classification=doc.classification if doc else "RESTRICTED",
        user_id=session.user_id,
        device_id=session.device_id,
        status=session.status,
        duration_seconds=session.session_duration_seconds,
        remaining_seconds=remaining,
        created_at=session.created_at,
        expires_at=session.expires_at,
        last_activity_at=session.last_activity_at,
        closed_at=session.closed_at,
        is_expired=is_expired,
    )


@router.post(
    "/documents/{document_id}/viewer-session",
    response_model=ViewerSessionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Authorize decryption and create a dedicated secure viewer session",
)
def create_viewer_session(
    document_id: str,
    payload: ViewerSessionCreateRequest = ViewerSessionCreateRequest(),
    x_device_id: Optional[str] = Header(None, alias="X-Device-ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_step_up_assurance()),
):
    """Enforces policy, recipient authorization, device registration, and multi-party approvals,
    executes authenticated decryption, generates an ML-DSA-65 signed provenance record,
    and returns a short-lived secure viewer session."""
    device_id = payload.device_id or x_device_id
    if device_id:
        dev = db.query(Device).filter(Device.id == device_id).first()
        if not dev or dev.status == "REVOKED" or dev.registration_status == "REVOKED" or dev.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Viewer session creation denied: device is revoked or unauthorized.",
            )

    try:
        viewer_session, _, _ = ViewerSessionService.create_viewer_session(
            db=db,
            document_id=document_id,
            user=current_user,
            device_id=device_id,
            approval_request_id=payload.approval_request_id,
            emergency_request_id=payload.emergency_request_id,
            duration_seconds=payload.duration_seconds or ViewerSessionService.DEFAULT_DURATION_SECONDS,
        )
        return _to_viewer_response(viewer_session)
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe),
        )
    except ValueError as ve:
        err_msg = str(ve)
        status_code = status.HTTP_404_NOT_FOUND if "not found" in err_msg.lower() else status.HTTP_400_BAD_REQUEST
        raise HTTPException(
            status_code=status_code,
            detail=err_msg,
        )


@router.get(
    "/viewer-sessions/{viewer_session_id}",
    response_model=ViewerSessionResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve active secure viewer session status and remaining validity",
)
def get_viewer_session(
    viewer_session_id: str,
    x_device_id: Optional[str] = Header(None, alias="X-Device-ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves session metadata, confirming user binding, device binding, and server-side expiration."""
    try:
        session = ViewerSessionService.get_viewer_session(
            db=db,
            session_id=viewer_session_id,
            user=current_user,
            device_id=x_device_id,
            allow_expired=True,
        )
        return _to_viewer_response(session)
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))


@router.get(
    "/viewer-sessions/{viewer_session_id}/content",
    status_code=status.HTTP_200_OK,
    summary="Controlled content delivery for an active secure viewer session",
)
def get_viewer_content(
    viewer_session_id: str,
    x_device_id: Optional[str] = Header(None, alias="X-Device-ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delivers decrypted document content strictly into memory for display inside the secure viewer.
    Enforces no-cache security headers and prevents permanent filesystem persistence."""
    try:
        content_bytes, mime_type, filename = ViewerSessionService.get_session_content(
            db=db,
            session_id=viewer_session_id,
            user=current_user,
            device_id=x_device_id,
        )

        headers = {
            "Cache-Control": "no-store, no-cache, must-revalidate, private, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": f'inline; filename="{filename}"',
            "Content-Security-Policy": "default-src 'self'",
        }

        return Response(content=content_bytes, media_type=mime_type, headers=headers)
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        err_msg = str(ve)
        if "VIEWER_FORMAT_UNSUPPORTED" in err_msg:
            raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=err_msg)
        if "not_found" in err_msg.lower() or "not found" in err_msg.lower() or "VIEWER_SESSION_NOT_FOUND" in err_msg:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=err_msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)


@router.post(
    "/viewer-sessions/{viewer_session_id}/heartbeat",
    response_model=ViewerHeartbeatResponse,
    status_code=status.HTTP_200_OK,
    summary="Update viewer activity timestamp",
)
def viewer_heartbeat(
    viewer_session_id: str,
    x_device_id: Optional[str] = Header(None, alias="X-Device-ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Refreshes last_activity_at. Does not extend server-side expiration deadline."""
    try:
        session = ViewerSessionService.heartbeat(
            db=db,
            session_id=viewer_session_id,
            user=current_user,
            device_id=x_device_id,
        )
        now = datetime.now(timezone.utc)
        exp = session.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        remaining = max(0, int((exp - now).total_seconds()))

        return ViewerHeartbeatResponse(
            viewer_session_id=session.id,
            status=session.status,
            last_activity_at=session.last_activity_at,
            expires_at=session.expires_at,
            remaining_seconds=remaining,
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))


@router.post(
    "/viewer-sessions/{viewer_session_id}/close",
    response_model=ViewerCloseResponse,
    status_code=status.HTTP_200_OK,
    summary="Explicitly close and terminate a secure viewer session",
)
def close_viewer_session(
    viewer_session_id: str,
    x_device_id: Optional[str] = Header(None, alias="X-Device-ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Terminates viewer session, marking it COMPLETED and preventing further content requests."""
    try:
        session = ViewerSessionService.close_viewer_session(
            db=db,
            session_id=viewer_session_id,
            user=current_user,
            device_id=x_device_id,
        )
        return ViewerCloseResponse(
            viewer_session_id=session.id,
            status=session.status,
            closed_at=session.closed_at or datetime.now(timezone.utc),
            message="Viewer session terminated successfully. Further content requests will be rejected.",
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
