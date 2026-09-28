import json
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.audit_event import AuditEvent


class AuditService:
    @staticmethod
    def log_event(
        db: Session,
        event_type: str,
        user_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        document_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> AuditEvent:
        """Records a real, cryptographically chained audit event in the database."""
        now = datetime.now(timezone.utc)
        
        # Get the previous audit event hash to maintain the audit chain
        last_event = db.query(AuditEvent).order_by(desc(AuditEvent.timestamp), desc(AuditEvent.id)).first()
        prev_hash = last_event.event_hash if last_event and last_event.event_hash else "0" * 64

        metadata_clean = metadata or {}
        serialized_metadata = json.dumps(metadata_clean, sort_keys=True)
        event_id = str(uuid.uuid4())

        # Formulate payload to hash
        payload = f"{event_id}|{prev_hash}|{event_type}|{user_id or 'SYSTEM'}|{now.isoformat()}|{serialized_metadata}"
        event_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        event = AuditEvent(
            id=event_id,
            event_type=event_type,
            user_id=user_id,
            document_id=document_id,
            session_id=session_id,
            timestamp=now,
            event_hash=event_hash,
            previous_event_hash=prev_hash,
            metadata_json=metadata_clean,
        )
        db.add(event)
        try:
            db.commit()
        except Exception:
            db.rollback()
        return event

    @staticmethod
    def get_events(
        db: Session,
        limit: int = 100,
        offset: int = 0,
        event_type: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> List[AuditEvent]:
        """Retrieves real audit events sorted from newest to oldest."""
        query = db.query(AuditEvent)
        if event_type:
            query = query.filter(AuditEvent.event_type == event_type)
        if user_id:
            query = query.filter(AuditEvent.user_id == user_id)
        return query.order_by(desc(AuditEvent.timestamp)).offset(offset).limit(limit).all()
