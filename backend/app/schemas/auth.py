from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict


class LoginRequest(BaseModel):
    username_or_email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    user_id: str
    username: str
    email: str
    role: str


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
