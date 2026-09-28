from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from app.models.mfa import UserMfaCredential
from app.schemas.auth import (
    MfaEnrollResponse,
    MfaVerifyRequest,
    MfaVerifyResponse,
    MfaLoginVerifyRequest,
    MfaStatusResponse,
    MfaStepUpRequest,
    MfaStepUpResponse,
    TokenResponse,
)
from app.security.permissions import get_current_user
from app.security.mfa_service import MfaService
from app.security.tokens import decode_access_token
from app.security.rate_limiter import auth_rate_limiter, get_client_ip
from app.services.auth_service import AuthService

router = APIRouter()


@router.get(
    "/status",
    response_model=MfaStatusResponse,
    summary="Get user MFA configuration status",
)
def get_mfa_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns the user's active MFA enrollment status without disclosing secrets."""
    cred = db.query(UserMfaCredential).filter(UserMfaCredential.user_id == current_user.id).first()
    if not cred or not cred.enabled:
        return MfaStatusResponse(enabled=False)
    return MfaStatusResponse(
        enabled=cred.enabled,
        method=cred.method,
        verified_at=cred.verified_at,
        last_used_at=cred.last_used_at,
    )


@router.post(
    "/enroll",
    response_model=MfaEnrollResponse,
    summary="Initiate RFC 6238 TOTP MFA enrollment",
)
def enroll_mfa(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generates a CSPRNG TOTP secret, encrypts it at rest, and returns provisioning data."""
    client_ip = get_client_ip(request)
    auth_rate_limiter.check_rate_limit(f"mfa_enroll:{current_user.id}", max_requests=10, window_seconds=300)
    auth_rate_limiter.check_rate_limit(f"mfa_enroll_ip:{client_ip}", max_requests=30, window_seconds=300)

    enrollment_data = MfaService.enroll_totp(db=db, user=current_user)
    return MfaEnrollResponse(
        method=enrollment_data["method"],
        provisioning_uri=enrollment_data["provisioning_uri"],
        secret=enrollment_data["secret"],
        status=enrollment_data["status"],
    )


@router.post(
    "/verify",
    response_model=MfaVerifyResponse,
    summary="Verify TOTP code to complete enrollment",
)
def verify_mfa_enrollment(
    verify_req: MfaVerifyRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verifies submitted TOTP code against the encrypted credential to enable MFA."""
    client_ip = get_client_ip(request)
    auth_rate_limiter.check_rate_limit(f"mfa_verify:{current_user.id}", max_requests=10, window_seconds=300)
    auth_rate_limiter.check_rate_limit(f"mfa_verify_ip:{client_ip}", max_requests=30, window_seconds=300)

    success, msg = MfaService.verify_enrollment(db=db, user=current_user, code=verify_req.code)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    # Issue fresh token with MFA_VERIFIED assurance
    now = datetime.now(timezone.utc)
    token_resp = AuthService.issue_token_for_user(
        db=db,
        user=current_user,
        auth_assurance_level="MFA_VERIFIED",
        mfa_verified_at=now,
    )
    return MfaVerifyResponse(
        verified=True,
        message=msg,
        auth_assurance_level="MFA_VERIFIED",
        access_token=token_resp.access_token,
    )


@router.post(
    "/verify-login",
    response_model=TokenResponse,
    summary="Complete multi-factor authentication during login",
)
def verify_mfa_login(
    login_req: MfaLoginVerifyRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Verifies MFA code for an unauthenticated user holding a valid mfa_token."""
    client_ip = get_client_ip(request)
    auth_rate_limiter.check_rate_limit(f"mfa_login_ip:{client_ip}", max_requests=20, window_seconds=300)

    payload = decode_access_token(login_req.mfa_token)
    if not payload or not payload.get("mfa_pending") or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA pre-authentication token.",
        )

    user_id = payload["sub"]
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
        )

    success, msg = MfaService.verify_totp(db=db, user=user, code=login_req.code)
    if not success:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=msg)

    now = datetime.now(timezone.utc)
    return AuthService.issue_token_for_user(
        db=db,
        user=user,
        device_id=login_req.device_id,
        auth_assurance_level="MFA_VERIFIED",
        mfa_verified_at=now,
        ip_metadata=client_ip,
        user_agent_metadata=request.headers.get("User-Agent", "")[:255],
    )


@router.post(
    "/step-up",
    response_model=MfaStepUpResponse,
    summary="Perform step-up MFA re-authentication for high-value operations",
)
def step_up_mfa(
    step_up_req: MfaStepUpRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Validates fresh TOTP and issues step-up assurance token for sensitive operations."""
    client_ip = get_client_ip(request)
    auth_rate_limiter.check_rate_limit(f"mfa_step_up:{current_user.id}", max_requests=10, window_seconds=300)
    auth_rate_limiter.check_rate_limit(f"mfa_step_up_ip:{client_ip}", max_requests=30, window_seconds=300)

    success, msg = MfaService.verify_totp(db=db, user=current_user, code=step_up_req.code, is_step_up=True)
    if not success:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=msg)

    now = datetime.now(timezone.utc)
    token_resp = AuthService.issue_token_for_user(
        db=db,
        user=current_user,
        auth_assurance_level="MFA_VERIFIED",
        mfa_verified_at=now,
    )

    return MfaStepUpResponse(
        success=True,
        auth_assurance_level="MFA_VERIFIED",
        mfa_verified_at=now,
        assurance_expires_in_seconds=900,
        access_token=token_resp.access_token,
    )
