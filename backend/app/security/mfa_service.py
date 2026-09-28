import os
import base64
from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional, Dict, Any
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyotp

from app.config.settings import settings
from app.models.mfa import UserMfaCredential
from app.models.user import User
from app.services.audit_service import AuditService


def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class MfaCrypto:
    """Protects TOTP secrets at rest using dedicated AES-256-GCM encryption key."""

    @staticmethod
    def encrypt_secret(secret_plaintext: str) -> Tuple[str, str]:
        """Encrypts a TOTP secret using the dedicated MFA_ENCRYPTION_KEY.
        Returns (encrypted_secret_base64, nonce_base64)."""
        key = settings.get_mfa_encryption_key_bytes()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit CSPRNG nonce
        ciphertext = aesgcm.encrypt(nonce, secret_plaintext.encode("utf-8"), None)
        return base64.b64encode(ciphertext).decode("utf-8"), base64.b64encode(nonce).decode("utf-8")

    @staticmethod
    def decrypt_secret(encrypted_secret_b64: str, nonce_b64: str) -> str:
        """Decrypts a TOTP secret using the dedicated MFA_ENCRYPTION_KEY."""
        key = settings.get_mfa_encryption_key_bytes()
        aesgcm = AESGCM(key)
        ciphertext = base64.b64decode(encrypted_secret_b64)
        nonce = base64.b64decode(nonce_b64)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode("utf-8")


class MfaService:
    """RFC 6238 TOTP Multi-Factor Authentication Service."""

    @staticmethod
    def get_user_mfa_credential(db: Session, user_id: str) -> Optional[UserMfaCredential]:
        return db.query(UserMfaCredential).filter(UserMfaCredential.user_id == user_id).first()

    @staticmethod
    def enroll_totp(
        db: Session,
        user: User,
        issuer_name: str = "SecureDocumentProvenance",
    ) -> Dict[str, Any]:
        """Initiates RFC 6238 TOTP enrollment.
        Generates a CSPRNG secret, stores it encrypted, and returns provisioning data.
        The plaintext secret is returned ONLY in this response and never logged or persisted in plain."""
        now = datetime.now(timezone.utc)

        # Generate CSPRNG base32 secret (160-bit standard)
        totp_secret = pyotp.random_base32()

        # Encrypt at rest with dedicated key
        enc_secret_b64, nonce_b64 = MfaCrypto.encrypt_secret(totp_secret)

        existing = MfaService.get_user_mfa_credential(db, user.id)
        if existing:
            existing.method = "TOTP"
            existing.encrypted_secret = enc_secret_b64
            existing.secret_nonce = nonce_b64
            existing.encryption_key_version = "v1"
            existing.enabled = False
            existing.verified_at = None
            existing.failed_attempt_count = 0
            existing.locked_until = None
            cred = existing
        else:
            cred = UserMfaCredential(
                user_id=user.id,
                method="TOTP",
                encrypted_secret=enc_secret_b64,
                secret_nonce=nonce_b64,
                encryption_key_version="v1",
                enabled=False,
                created_at=now,
                failed_attempt_count=0,
            )
            db.add(cred)

        db.commit()
        db.refresh(cred)

        # Audit event without logging secret
        AuditService.log_event(
            db=db,
            event_type="MFA_ENROLLMENT_STARTED",
            user_id=user.id,
            metadata={"method": "TOTP", "credential_id": cred.id},
        )

        totp = pyotp.TOTP(totp_secret)
        provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name=issuer_name)

        return {
            "method": "TOTP",
            "provisioning_uri": provisioning_uri,
            "secret": totp_secret,  # Returned once to enrollment client
            "status": "ENROLLMENT_PENDING_VERIFICATION",
        }

    @staticmethod
    def verify_enrollment(
        db: Session,
        user: User,
        code: str,
    ) -> Tuple[bool, str]:
        """Verifies enrollment code and enables MFA upon success."""
        cred = MfaService.get_user_mfa_credential(db, user.id)
        if not cred:
            return False, "MFA enrollment has not been initiated for this account."

        now = datetime.now(timezone.utc)
        locked_at = _to_utc(cred.locked_until)
        if locked_at and locked_at > now:
            return False, "MFA credential is temporarily locked due to repeated failed attempts."

        try:
            secret = MfaCrypto.decrypt_secret(cred.encrypted_secret, cred.secret_nonce)
        except Exception:
            return False, "Failed to decrypt MFA credential."

        totp = pyotp.TOTP(secret)
        # RFC 6238 verification with +/- 1 time-step drift tolerance
        is_valid = totp.verify(code.strip(), valid_window=1)

        if not is_valid:
            cred.failed_attempt_count += 1
            if cred.failed_attempt_count >= 5:
                cred.locked_until = now + timedelta(minutes=15)
                AuditService.log_event(
                    db=db,
                    event_type="MFA_VERIFICATION_FAILURE",
                    user_id=user.id,
                    metadata={"reason": "lockout_triggered", "failed_attempts": cred.failed_attempt_count},
                )
            else:
                AuditService.log_event(
                    db=db,
                    event_type="MFA_VERIFICATION_FAILURE",
                    user_id=user.id,
                    metadata={"failed_attempts": cred.failed_attempt_count},
                )
            db.commit()
            return False, "Invalid TOTP verification code."

        # Success - enable MFA
        cred.enabled = True
        cred.verified_at = now
        cred.last_used_at = now
        cred.failed_attempt_count = 0
        cred.locked_until = None
        db.commit()

        AuditService.log_event(
            db=db,
            event_type="MFA_ENROLLMENT_VERIFIED",
            user_id=user.id,
            metadata={"method": "TOTP"},
        )
        AuditService.log_event(
            db=db,
            event_type="MFA_ENABLED",
            user_id=user.id,
            metadata={"method": "TOTP"},
        )
        return True, "MFA has been successfully verified and enabled."

    @staticmethod
    def verify_totp(
        db: Session,
        user: User,
        code: str,
        is_step_up: bool = False,
    ) -> Tuple[bool, str]:
        """Validates a submitted TOTP code against the user's active MFA credential."""
        cred = MfaService.get_user_mfa_credential(db, user.id)
        if not cred or not cred.enabled:
            return False, "MFA is not enabled for this user."

        now = datetime.now(timezone.utc)
        locked_at = _to_utc(cred.locked_until)
        if locked_at and locked_at > now:
            return False, "MFA credential is temporarily locked due to repeated failed attempts."

        try:
            secret = MfaCrypto.decrypt_secret(cred.encrypted_secret, cred.secret_nonce)
        except Exception:
            return False, "Failed to decrypt MFA credential."

        totp = pyotp.TOTP(secret)
        # Verify with +/- 1 time-step drift tolerance
        is_valid = totp.verify(code.strip(), valid_window=1)

        if not is_valid:
            cred.failed_attempt_count += 1
            if cred.failed_attempt_count >= 5:
                cred.locked_until = now + timedelta(minutes=15)
                event_name = "STEP_UP_AUTH_FAILURE" if is_step_up else "MFA_VERIFICATION_FAILURE"
                AuditService.log_event(
                    db=db,
                    event_type=event_name,
                    user_id=user.id,
                    metadata={"reason": "lockout_triggered", "failed_attempts": cred.failed_attempt_count},
                )
            else:
                event_name = "STEP_UP_AUTH_FAILURE" if is_step_up else "MFA_VERIFICATION_FAILURE"
                AuditService.log_event(
                    db=db,
                    event_type=event_name,
                    user_id=user.id,
                    metadata={"failed_attempts": cred.failed_attempt_count},
                )
            db.commit()
            return False, "Invalid TOTP code."

        # Replay prevention within current 30s step
        time_step = int(now.timestamp()) // 30
        if cred.last_used_at:
            last_step = int(cred.last_used_at.timestamp()) // 30
            if time_step == last_step:
                return False, "TOTP code has already been used. Please wait for the next time-step."

        cred.last_used_at = now
        cred.failed_attempt_count = 0
        cred.locked_until = None
        db.commit()

        event_name = "STEP_UP_AUTH_SUCCESS" if is_step_up else "MFA_VERIFICATION_SUCCESS"
        AuditService.log_event(
            db=db,
            event_type=event_name,
            user_id=user.id,
            metadata={"method": "TOTP", "is_step_up": is_step_up},
        )
        return True, "Verification successful."
