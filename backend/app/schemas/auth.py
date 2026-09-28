from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, ConfigDict


class LoginRequest(BaseModel):
    username_or_email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)
    device_id: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in_minutes: Optional[int] = None
    user_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None
    auth_assurance_level: str = "NORMAL"
    session_id: Optional[str] = None


class LogoutResponse(BaseModel):
    message: str = "Successfully logged out. Session invalidated."


class UserResponse(BaseModel):
    id: str
    username: str
    email: EmailStr
    role: str
    department_id: Optional[str] = None
    department_name: Optional[str] = None
    is_active: bool
    mfa_enabled: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AdminCreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)
    role: str
    department_id: Optional[str] = None


class AdminUpdateUserRequest(BaseModel):
    role: Optional[str] = None
    department_id: Optional[str] = None
    is_active: Optional[bool] = None


class PasswordResetRequest(BaseModel):
    new_password: str = Field(..., min_length=12, max_length=128)


# MFA Schemas
class MfaEnrollResponse(BaseModel):
    method: str
    provisioning_uri: str
    secret: str
    status: str


class MfaVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)


class MfaVerifyResponse(BaseModel):
    verified: bool
    message: str
    auth_assurance_level: Optional[str] = None
    access_token: Optional[str] = None


class MfaLoginVerifyRequest(BaseModel):
    mfa_token: str
    code: str = Field(..., min_length=6, max_length=8)
    device_id: Optional[str] = None


class MfaStatusResponse(BaseModel):
    enabled: bool
    method: Optional[str] = None
    verified_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


class MfaStepUpRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)


class MfaStepUpResponse(BaseModel):
    success: bool
    auth_assurance_level: str
    mfa_verified_at: datetime
    assurance_expires_in_seconds: int
    access_token: str


# Session Schemas
class SessionResponse(BaseModel):
    id: str
    user_id: str
    device_id: Optional[str] = None
    created_at: datetime
    last_activity_at: datetime
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    authentication_level: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)
