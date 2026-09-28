from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class ViewerSessionCreateRequest(BaseModel):
    device_id: Optional[str] = Field(None, description="Client device ID for hardware/registered device binding")
    approval_request_id: Optional[str] = Field(None, description="Optional approved multi-party approval request ID")
    emergency_request_id: Optional[str] = Field(None, description="Optional authorized emergency break-glass request ID")
    duration_seconds: Optional[int] = Field(900, ge=60, le=3600, description="Requested session lifetime in seconds (default: 15 min)")


class ViewerSessionResponse(BaseModel):
    viewer_session_id: str
    decryption_session_id: str
    provenance_event_id: Optional[str] = None
    document_id: str
    document_title: Optional[str] = None
    original_filename: str
    mime_type: str
    classification: str
    user_id: str
    device_id: Optional[str] = None
    status: str
    duration_seconds: int
    remaining_seconds: int
    created_at: datetime
    expires_at: datetime
    last_activity_at: datetime
    closed_at: Optional[datetime] = None
    is_expired: bool


class ViewerHeartbeatResponse(BaseModel):
    viewer_session_id: str
    status: str
    last_activity_at: datetime
    expires_at: datetime
    remaining_seconds: int


class ViewerCloseResponse(BaseModel):
    viewer_session_id: str
    status: str
    closed_at: datetime
    message: str
