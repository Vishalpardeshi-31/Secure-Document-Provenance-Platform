from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class DeviceRegisterRequest(BaseModel):
    device_name: str = Field(..., min_length=2, max_length=128)
    device_fingerprint: str = Field(..., min_length=16, max_length=255)


class DeviceStatusUpdateRequest(BaseModel):
    registration_status: str = Field(..., pattern=r"^(PENDING|ACTIVE|REVOKED)$")


class DeviceResponse(BaseModel):
    id: str
    user_id: str
    device_name: str
    device_fingerprint: str
    registration_status: str
    created_at: datetime
    last_seen_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
