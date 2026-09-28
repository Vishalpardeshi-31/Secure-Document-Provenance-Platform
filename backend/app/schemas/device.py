from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class DeviceRegisterRequest(BaseModel):
    device_name: str = Field(..., min_length=2, max_length=128)
    device_fingerprint: str = Field(..., min_length=16, max_length=255)
    public_key: Optional[str] = Field(None, max_length=512)


class DeviceStatusUpdateRequest(BaseModel):
    registration_status: str = Field(..., pattern=r"^(PENDING|ACTIVE|REVOKED)$")


class DeviceChallengeResponse(BaseModel):
    device_id: str
    challenge_nonce: str
    expires_in_seconds: int = 300


class DeviceChallengeVerifyRequest(BaseModel):
    signature_hex: str = Field(..., min_length=32, max_length=512)


class DeviceChallengeVerifyResponse(BaseModel):
    device_id: str
    verified: bool
    message: str


class DeviceResponse(BaseModel):
    id: str
    user_id: str
    device_name: str
    device_fingerprint: str
    registration_status: str
    status: Optional[str] = None
    public_key: Optional[str] = None
    created_at: datetime
    last_seen_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
