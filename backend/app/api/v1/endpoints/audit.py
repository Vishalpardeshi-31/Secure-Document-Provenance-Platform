from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import User
from app.models.role import UserRole
from app.schemas.audit import AuditEventResponse
from app.services.audit_service import AuditService
from app.security.permissions import require_any_role

router = APIRouter()


@router.get(
    "/events",
    response_model=List[AuditEventResponse],
    summary="List security audit events (Admin or Auditor only)",
)
def list_audit_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    auditor_or_admin: User = Depends(require_any_role(UserRole.ADMIN, UserRole.AUDITOR)),
):
    """Retrieves real, non-fabricated security audit events from the database.
    Accessible only to ADMIN and AUDITOR roles."""
    events = AuditService.get_events(
        db=db,
        limit=limit,
        offset=offset,
        event_type=event_type,
        user_id=user_id,
    )
    return [
        AuditEventResponse(
            id=e.id,
            event_type=e.event_type,
            user_id=e.user_id,
            document_id=e.document_id,
            session_id=e.session_id,
            timestamp=e.timestamp,
            event_hash=e.event_hash,
            previous_event_hash=e.previous_event_hash,
            metadata_json=e.metadata_json,
        )
        for e in events
    ]
