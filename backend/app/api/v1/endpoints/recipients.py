import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from app.models.role import UserRole
from app.models.recipient_key import RecipientKey
from app.security.permissions import require_authenticated_user, require_role, require_any_role
from app.security.recipient_key_manager import RecipientKeyManager
from app.schemas.recipient import (
    RecipientKeyStatusResponse,
    RecipientUserSummary,
    RecipientKeyDetailResponse,
)

logger = logging.getLogger("secure_document_platform.api.recipients")

router = APIRouter(prefix="/recipients", tags=["Recipient Key Management"])


@router.get("", response_model=List[RecipientUserSummary])
def list_recipients(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_role(UserRole.ADMIN, UserRole.OFFICER)),
) -> List[RecipientUserSummary]:
    """Lists users eligible to receive encrypted documents along with their active cryptographic key status.
    
    Accessible by ADMIN and OFFICER (officers use this list to select valid recipients during upload).
    """
    recipient_users = (
        db.query(User)
        .filter(User.role == UserRole.RECIPIENT.value)
        .order_by(User.username)
        .all()
    )

    results = []
    for u in recipient_users:
        active_key = RecipientKeyManager.get_active_key(db, u.id)
        results.append(
            RecipientUserSummary(
                id=u.id,
                username=u.username,
                email=u.email,
                is_active=u.is_active,
                has_active_key=active_key is not None,
                active_key_version=active_key.key_version if active_key else None,
                active_key_id=active_key.id if active_key else None,
                key_algorithm=active_key.algorithm if active_key else None,
            )
        )
    return results


@router.get("/{recipient_id}/key-status", response_model=RecipientKeyStatusResponse)
def get_recipient_key_status(
    recipient_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
) -> RecipientKeyStatusResponse:
    """Retrieves safe cryptographic key metadata for a recipient.
    
    Accessible by ADMIN, OFFICER, or the recipient user themselves.
    """
    if current_user.role not in (UserRole.ADMIN.value, UserRole.OFFICER.value) and current_user.id != recipient_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: You cannot view cryptographic key status for other users.",
        )

    user = db.query(User).filter(User.id == recipient_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recipient with ID '{recipient_id}' not found.",
        )

    active_key = RecipientKeyManager.get_active_key(db, user.id)
    return RecipientKeyStatusResponse(
        user_id=user.id,
        username=user.username,
        has_active_key=active_key is not None,
        active_key_id=active_key.id if active_key else None,
        active_key_version=active_key.key_version if active_key else None,
        algorithm=active_key.algorithm if active_key else None,
        created_at=active_key.created_at if active_key else None,
        status=active_key.status if active_key else None,
    )


@router.post("/{recipient_id}/provision-key", response_model=RecipientKeyDetailResponse)
def provision_recipient_key(
    recipient_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
) -> RecipientKeyDetailResponse:
    """Provisions a fresh post-quantum ML-KEM-768 key pair for the specified recipient user.
    
    Protected private key is stored encrypted at rest under a dedicated server key-protection key.
    Raw private key is never returned across API or logged.
    Accessible only by ADMIN.
    """
    user = db.query(User).filter(User.id == recipient_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recipient with ID '{recipient_id}' not found.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot provision key for inactive recipient '{user.username}'.",
        )

    try:
        key_record = RecipientKeyManager.provision_recipient_key(
            db=db,
            user=user,
            actor=current_user,
        )
        return RecipientKeyDetailResponse(
            id=key_record.id,
            user_id=key_record.user_id,
            key_version=key_record.key_version,
            algorithm=key_record.algorithm,
            status=key_record.status,
            created_at=key_record.created_at,
            revoked_at=key_record.revoked_at,
        )
    except Exception as exc:
        logger.error(f"Failed to provision recipient key: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to provision cryptographic key: {exc}",
        )


@router.post("/{recipient_id}/revoke-key", response_model=RecipientKeyDetailResponse)
def revoke_recipient_key(
    recipient_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
) -> RecipientKeyDetailResponse:
    """Revokes the currently active cryptographic key of a recipient.
    
    Revoked keys cannot be used for any new document encryption distributions.
    Historical records remain intact for provenance.
    Accessible only by ADMIN.
    """
    user = db.query(User).filter(User.id == recipient_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recipient with ID '{recipient_id}' not found.",
        )

    active_key = RecipientKeyManager.get_active_key(db, user.id)
    if not active_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Recipient '{user.username}' does not have an active key to revoke.",
        )

    try:
        revoked_key = RecipientKeyManager.revoke_key(
            db=db,
            key_id=active_key.id,
            actor=current_user,
        )
        return RecipientKeyDetailResponse(
            id=revoked_key.id,
            user_id=revoked_key.user_id,
            key_version=revoked_key.key_version,
            algorithm=revoked_key.algorithm,
            status=revoked_key.status,
            created_at=revoked_key.created_at,
            revoked_at=revoked_key.revoked_at,
        )
    except Exception as exc:
        logger.error(f"Failed to revoke recipient key: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke cryptographic key: {exc}",
        )
