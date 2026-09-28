import os
import secrets
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.device import Device
from app.models.viewer_session import ViewerSession
from app.services.audit_service import AuditService


def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class DeviceService:
    @staticmethod
    def get_by_id(db: Session, device_id: str) -> Optional[Device]:
        return db.query(Device).filter(Device.id == device_id).first()

    @staticmethod
    def list_user_devices(db: Session, user_id: str) -> List[Device]:
        return db.query(Device).filter(Device.user_id == user_id).order_by(desc(Device.created_at)).all()

    @staticmethod
    def list_all_devices(db: Session) -> List[Device]:
        return db.query(Device).order_by(desc(Device.created_at)).all()

    @staticmethod
    def register_device(
        db: Session,
        user_id: str,
        device_name: str,
        device_fingerprint: str,
        public_key: Optional[str] = None,
    ) -> Device:
        """Registers a user device foundation record with cryptographic binding and status tracking."""
        now = datetime.now(timezone.utc)
        
        # Check if identical device fingerprint already exists for this user
        existing = db.query(Device).filter(
            Device.user_id == user_id,
            Device.device_fingerprint == device_fingerprint
        ).first()

        import hashlib
        device_hash = hashlib.sha256(device_fingerprint.encode("utf-8")).hexdigest()

        if existing:
            # If device was previously REVOKED, do not silently reactivate
            if existing.registration_status == "REVOKED" or existing.status == "REVOKED":
                # Create a fresh device registration record for re-registration
                device = Device(
                    user_id=user_id,
                    device_name=device_name,
                    device_fingerprint=f"{device_fingerprint}-{secrets.token_hex(4)}",
                    device_identifier_hash=device_hash,
                    public_key=public_key,
                    registration_status="ACTIVE",
                    status="ACTIVE",
                    registered_at=now,
                    last_seen_at=now,
                )
                db.add(device)
                db.commit()
                db.refresh(device)
                AuditService.log_event(
                    db=db,
                    event_type="DEVICE_REGISTERED",
                    user_id=user_id,
                    metadata={"device_id": device.id, "device_name": device.device_name, "status": "ACTIVE"},
                )
                return device

            existing.last_seen_at = now
            existing.device_name = device_name
            existing.device_identifier_hash = device_hash
            if public_key:
                existing.public_key = public_key
            if not getattr(existing, "status", None):
                existing.status = existing.registration_status
            db.commit()
            db.refresh(existing)
            return existing

        device = Device(
            user_id=user_id,
            device_name=device_name,
            device_fingerprint=device_fingerprint,
            device_identifier_hash=device_hash,
            public_key=public_key,
            registration_status="ACTIVE",
            status="ACTIVE",
            registered_at=now,
            last_seen_at=now,
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        AuditService.log_event(
            db=db,
            event_type="DEVICE_REGISTERED",
            user_id=user_id,
            metadata={
                "device_id": device.id,
                "device_name": device.device_name,
                "registration_status": device.registration_status,
                "status": device.status,
            },
        )
        return device

    @staticmethod
    def update_device_status(
        db: Session,
        device_id: str,
        status: str,
        actor_id: Optional[str] = None,
    ) -> Device:
        device = DeviceService.get_by_id(db, device_id)
        if not device:
            raise ValueError(f"Device with ID '{device_id}' does not exist.")

        valid_statuses = ["PENDING", "ACTIVE", "REVOKED"]
        norm_status = status.upper()
        if norm_status not in valid_statuses:
            raise ValueError(f"Invalid status '{status}'. Allowed: {', '.join(valid_statuses)}")

        # Enforce Requirement 13: Revoked devices cannot be reactivated via simple status toggle
        if device.registration_status == "REVOKED" and norm_status != "REVOKED":
            raise ValueError(
                "Revoked devices cannot be directly reactivated. Re-authorization requires full device re-registration."
            )

        now = datetime.now(timezone.utc)
        old_status = device.registration_status
        device.registration_status = norm_status
        device.status = norm_status
        if norm_status == "REVOKED":
            device.revoked_at = now
            # Terminate active viewer sessions associated with this device or user
            viewer_sessions = db.query(ViewerSession).filter(
                ViewerSession.user_id == device.user_id,
                ViewerSession.status == "ACTIVE"
            ).all()
            for vs in viewer_sessions:
                vs.status = "TERMINATED"

        db.commit()
        db.refresh(device)

        if norm_status == "REVOKED":
            AuditService.log_event(
                db=db,
                event_type="DEVICE_REVOKED",
                user_id=actor_id or device.user_id,
                metadata={
                    "device_id": device.id,
                    "old_status": old_status,
                    "new_status": norm_status,
                },
            )

        return device

    @staticmethod
    def revoke_device(db: Session, device_id: str, actor_id: str) -> Device:
        """Explicitly revokes a device and terminates associated viewer sessions."""
        return DeviceService.update_device_status(db=db, device_id=device_id, status="REVOKED", actor_id=actor_id)

    @staticmethod
    def create_challenge(db: Session, device_id: str) -> str:
        """Creates a cryptographically random challenge nonce for device verification."""
        device = DeviceService.get_by_id(db, device_id)
        if not device:
            raise ValueError(f"Device '{device_id}' not found.")
        if device.status != "ACTIVE":
            raise ValueError(f"Device '{device_id}' is not ACTIVE.")

        now = datetime.now(timezone.utc)
        nonce = secrets.token_hex(32)
        device.challenge_nonce = nonce
        device.challenge_expires_at = now + timedelta(minutes=5)
        db.commit()
        return nonce

    @staticmethod
    def verify_challenge(
        db: Session,
        device_id: str,
        signature_hex: str,
    ) -> bool:
        """Verifies signature of challenge nonce against device public key."""
        device = DeviceService.get_by_id(db, device_id)
        if not device or device.status != "ACTIVE":
            return False

        now = datetime.now(timezone.utc)
        if not device.challenge_nonce or not device.challenge_expires_at:
            return False
        exp_utc = _to_utc(device.challenge_expires_at)
        if exp_utc and exp_utc < now:
            return False

        if not device.public_key:
            # Without public key, challenge verification fails
            AuditService.log_event(
                db=db,
                event_type="DEVICE_CHALLENGE_FAILURE",
                user_id=device.user_id,
                metadata={"device_id": device_id, "reason": "no_public_key"},
            )
            return False

        import base64
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.exceptions import InvalidSignature

        verified = False
        try:
            pub_bytes = base64.b64decode(device.public_key)
            sig_bytes = bytes.fromhex(signature_hex)
            challenge_bytes = device.challenge_nonce.encode("utf-8")

            if len(pub_bytes) == 32:
                # Ed25519
                pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
                pub_key.verify(sig_bytes, challenge_bytes)
                verified = True
        except (InvalidSignature, Exception):
            verified = False

        # Reset challenge nonce once used
        device.challenge_nonce = None
        device.challenge_expires_at = None

        if verified:
            device.last_seen_at = now
            db.commit()
            AuditService.log_event(
                db=db,
                event_type="DEVICE_CHALLENGE_SUCCESS",
                user_id=device.user_id,
                metadata={"device_id": device_id},
            )
            return True
        else:
            db.commit()
            AuditService.log_event(
                db=db,
                event_type="DEVICE_CHALLENGE_FAILURE",
                user_id=device.user_id,
                metadata={"device_id": device_id, "reason": "invalid_signature"},
            )
            return False

    @staticmethod
    def delete_device(db: Session, device_id: str, user_id: Optional[str] = None) -> None:
        query = db.query(Device).filter(Device.id == device_id)
        if user_id:
            query = query.filter(Device.user_id == user_id)
        device = query.first()
        if not device:
            raise ValueError(f"Device with ID '{device_id}' does not exist.")

        db.delete(device)
        db.commit()
