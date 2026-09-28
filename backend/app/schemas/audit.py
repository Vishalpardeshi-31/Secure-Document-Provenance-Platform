from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict


class AuditEventResponse(BaseModel):
    id: str
    event_type: str
    user_id: Optional[str] = None
    document_id: Optional[str] = None
    session_id: Optional[str] = None
    timestamp: datetime
    event_hash: str
    previous_event_hash: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)
