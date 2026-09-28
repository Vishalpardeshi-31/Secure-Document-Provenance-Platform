from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class DecryptionRequest(BaseModel):
    device_id: Optional[str] = None
    approval_request_id: Optional[str] = None
    emergency_request_id: Optional[str] = None



class DecryptionResultResponse(BaseModel):
    session_id: str
    document_id: str
    status: str
    original_filename: str
    mime_type: str
    original_size_bytes: int
    plaintext_sha256: str
    plaintext_base64: str
    completed_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DecryptionSessionResponse(BaseModel):
    id: str
    document_id: str
    user_id: str
    device_id: Optional[str] = None
    policy_id: Optional[str] = None
    status: str
    started_at: datetime
    authorized_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    failure_reason_code: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
