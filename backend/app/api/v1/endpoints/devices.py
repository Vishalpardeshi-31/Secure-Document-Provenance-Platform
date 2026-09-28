from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import User
from app.models.role import UserRole
from app.schemas.device import (
    DeviceRegisterRequest,
    DeviceStatusUpdateRequest,
    DeviceResponse,
    DeviceChallengeResponse,
    DeviceChallengeVerifyRequest,
    DeviceChallengeVerifyResponse,
)
from app.schemas.common import MessageResponse
from app.services.device_service import DeviceService
from app.security.permissions import get_current_user

router = APIRouter()


@router.get(
    "",
    response_model=List[DeviceResponse],
    summary="List registered devices",
)
def list_devices(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists registered devices. Admins see all devices; others see their own."""
    if current_user.role == UserRole.ADMIN.value:
        devices = DeviceService.list_all_devices(db=db)
    else:
        devices = DeviceService.list_user_devices(db=db, user_id=current_user.id)

    return [
        DeviceResponse(
            id=d.id,
            user_id=d.user_id,
            device_name=d.device_name,
            device_fingerprint=d.device_fingerprint,
            registration_status=d.registration_status,
            status=d.status,
            public_key=d.public_key,
            created_at=d.created_at,
            last_seen_at=d.last_seen_at,
            revoked_at=d.revoked_at,
        )
        for d in devices
    ]


@router.post(
    "",
    response_model=DeviceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a client device foundation record",
)
def register_device(
    request: DeviceRegisterRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Registers an authorized device foundation record for the authenticated user."""
    device = DeviceService.register_device(
        db=db,
        user_id=current_user.id,
        device_name=request.device_name,
        device_fingerprint=request.device_fingerprint,
        public_key=request.public_key,
    )
    return DeviceResponse(
        id=device.id,
        user_id=device.user_id,
        device_name=device.device_name,
        device_fingerprint=device.device_fingerprint,
        registration_status=device.registration_status,
        status=device.status,
        public_key=device.public_key,
        created_at=device.created_at,
        last_seen_at=device.last_seen_at,
        revoked_at=device.revoked_at,
    )


@router.post(
    "/{device_id}/revoke",
    response_model=DeviceResponse,
    summary="Revoke an authorized device",
)
def revoke_device(
    device_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Explicitly revokes a device and terminates active sessions."""
    device = DeviceService.get_by_id(db, device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")

    if current_user.role != UserRole.ADMIN.value and device.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    try:
        updated = DeviceService.revoke_device(db=db, device_id=device_id, actor_id=current_user.id)
        return DeviceResponse(
            id=updated.id,
            user_id=updated.user_id,
            device_name=updated.device_name,
            device_fingerprint=updated.device_fingerprint,
            registration_status=updated.registration_status,
            status=updated.status,
            public_key=updated.public_key,
            created_at=updated.created_at,
            last_seen_at=updated.last_seen_at,
            revoked_at=updated.revoked_at,
        )
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.post(
    "/{device_id}/challenge",
    response_model=DeviceChallengeResponse,
    summary="Issue a challenge nonce to registered device",
)
def issue_device_challenge(
    device_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Issues a cryptographically random challenge nonce for device verification."""
    device = DeviceService.get_by_id(db, device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")

    if current_user.role != UserRole.ADMIN.value and device.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    if device.status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Device is {device.status}. Only ACTIVE devices can be challenged.",
        )

    try:
        nonce = DeviceService.create_challenge(db, device_id)
        return DeviceChallengeResponse(
            device_id=device_id,
            challenge_nonce=nonce,
            expires_in_seconds=300,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/{device_id}/verify-challenge",
    response_model=DeviceChallengeVerifyResponse,
    summary="Verify device cryptographic signature on challenge nonce",
)
def verify_device_challenge(
    device_id: str,
    request: DeviceChallengeVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Verifies that the device possesses the corresponding private key for its registered public key."""
    device = DeviceService.get_by_id(db, device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")

    if current_user.role != UserRole.ADMIN.value and device.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    verified = DeviceService.verify_challenge(db, device_id, request.signature_hex)
    if not verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device challenge verification failed. Signature is invalid or expired.",
        )

    return DeviceChallengeVerifyResponse(
        device_id=device_id,
        verified=True,
        message="Device identity cryptographically verified.",
    )


@router.patch(
    "/{device_id}",
    response_model=DeviceResponse,
    summary="Update device registration status",
)
def update_device_status(
    device_id: str,
    request: DeviceStatusUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Updates device status (PENDING, ACTIVE, REVOKED)."""
    device = DeviceService.get_by_id(db, device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")

    if current_user.role != UserRole.ADMIN.value and device.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    try:
        updated = DeviceService.update_device_status(
            db=db,
            device_id=device_id,
            status=request.registration_status,
            actor_id=current_user.id,
        )
        return DeviceResponse(
            id=updated.id,
            user_id=updated.user_id,
            device_name=updated.device_name,
            device_fingerprint=updated.device_fingerprint,
            registration_status=updated.registration_status,
            status=updated.status,
            public_key=updated.public_key,
            created_at=updated.created_at,
            last_seen_at=updated.last_seen_at,
            revoked_at=updated.revoked_at,
        )
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.delete(
    "/{device_id}",
    response_model=MessageResponse,
    summary="Unregister/delete a device",
)
def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Deletes device registration."""
    device = DeviceService.get_by_id(db, device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")

    if current_user.role != UserRole.ADMIN.value and device.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    DeviceService.delete_device(db=db, device_id=device_id)
    return MessageResponse(message=f"Device '{device_id}' removed successfully.")
