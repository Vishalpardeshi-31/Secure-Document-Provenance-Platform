from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.device import Device
from app.services.audit_service import AuditService


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
    ) -> Device:
        """Registers a user device foundation record with status tracking."""
        now = datetime.now(timezone.utc)
        
        # Check if identical device fingerprint already exists for this user
        existing = db.query(Device).filter(
            Device.user_id == user_id,
            Device.device_fingerprint == device_fingerprint
        ).first()

        import hashlib
        device_hash = hashlib.sha256(device_fingerprint.encode("utf-8")).hexdigest()

        if existing:
            existing.last_seen_at = now
            existing.device_name = device_name
            existing.device_identifier_hash = device_hash
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

        now = datetime.now(timezone.utc)
        old_status = device.registration_status
        device.registration_status = norm_status
        device.status = norm_status
        if norm_status == "REVOKED":
            device.revoked_at = now

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
    def delete_device(db: Session, device_id: str, user_id: Optional[str] = None) -> None:
        query = db.query(Device).filter(Device.id == device_id)
        if user_id:
            query = query.filter(Device.user_id == user_id)
        device = query.first()
        if not device:
            raise ValueError(f"Device with ID '{device_id}' does not exist.")

        db.delete(device)
        db.commit()
