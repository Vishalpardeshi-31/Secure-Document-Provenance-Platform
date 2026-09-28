"""Recipient Key Manager for post-quantum ML-KEM-768 recipient key pairs."""
import base64
import json
import logging
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc

from cryptography.hazmat.primitives.asymmetric import mlkem
from app.config.settings import settings
from app.models.user import User
from app.models.recipient_key import RecipientKey
from app.crypto.ml_kem import MLKEMService
from app.crypto.key_protection import KeyProtectionService
from app.crypto.models import ProtectedPrivateKeyMaterial
from app.crypto.aes_gcm import AESGCMService
from app.services.audit_service import AuditService

logger = logging.getLogger("secure_document_platform.recipient_key_manager")


class RecipientKeyManager:
    """Manages asymmetric recipient cryptographic keys (ML-KEM-768).
    
    Responsibilities:
    - Generate post-quantum ML-KEM-768 key pairs using FIPS 203 standard primitives.
    - Register public keys.
    - Protect private keys at rest using Argon2id-derived keys from authentication secrets + AES-256-GCM.
    - Enforce key versioning (v1, v2, ...) and lifecycle transitions (ACTIVE, RETIRED, REVOKED).
    - Provide controlled internal-only private key decapsulation (never exposed to API/frontend).
    - Guarantee key hierarchy separation (Document DEK != Document KEK != Recipient KEK).
    """

    ALGORITHM = "ML-KEM-768"

    @staticmethod
    def get_recipient_protection_kek() -> bytes:
        """Retrieves legacy verified 32-byte key-protection key for Phase 4 backward compatibility."""
        return settings.get_recipient_kek_bytes()

    @staticmethod
    def generate_key_pair() -> Tuple[mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey]:
        """Generates a fresh post-quantum standard ML-KEM-768 key pair."""
        return MLKEMService.generate_key_pair()

    @classmethod
    def protect_private_key(
        cls,
        priv: mlkem.MLKEM768PrivateKey,
        user_id: str,
        key_version: int,
        auth_secret: Optional[str] = None,
    ) -> ProtectedPrivateKeyMaterial:
        """Protects the private key seed at rest using Argon2id and AES-256-GCM."""
        effective_secret = auth_secret or "SDP-AUTH-SECRET-DEFAULT"
        return KeyProtectionService.protect_private_key(
            priv=priv,
            auth_secret=effective_secret,
            user_id=user_id,
            key_version=key_version,
        )

    @classmethod
    def _unwrap_private_key(
        cls,
        recipient_key: RecipientKey,
        auth_secret: Optional[str] = None,
    ) -> mlkem.MLKEM768PrivateKey:
        """INTERNAL ONLY: Recovers the ML-KEM-768 private key for internal operations or tests.
        
        CRITICAL: Never expose this method or its return value to any REST API or frontend.
        """
        if recipient_key.status == "REVOKED":
            raise ValueError(f"Cannot unwrap private key: key version {recipient_key.key_version} is REVOKED.")

        # Check if key was protected with Argon2id metadata (Phase 6 / hardened model)
        if recipient_key.kdf_salt and recipient_key.encryption_nonce:
            effective_secret = auth_secret
            if not effective_secret and recipient_key.user:
                effective_secret = recipient_key.user.password_hash
            if not effective_secret:
                effective_secret = "SDP-AUTH-SECRET-DEFAULT"

            params = {}
            if recipient_key.kdf_parameters:
                try:
                    params = json.loads(recipient_key.kdf_parameters)
                except Exception:
                    params = {}

            protected = ProtectedPrivateKeyMaterial(
                encrypted_private_key=recipient_key.encrypted_private_key,
                kdf_algorithm=recipient_key.kdf_algorithm or "Argon2id",
                kdf_salt=recipient_key.kdf_salt,
                kdf_parameters=params,
                encryption_algorithm=recipient_key.encryption_algorithm or "AES-256-GCM",
                encryption_nonce=recipient_key.encryption_nonce,
                key_version=recipient_key.key_version,
            )
            return KeyProtectionService.recover_private_key(
                protected=protected,
                auth_secret=effective_secret,
                user_id=recipient_key.user_id,
            )

        # Legacy Phase 4 fallback: server KEK envelope
        rkek = cls.get_recipient_protection_kek()
        envelope = base64.b64decode(recipient_key.encrypted_private_key)
        if len(envelope) < AESGCMService.NONCE_SIZE_BYTES + AESGCMService.TAG_SIZE_BYTES:
            raise ValueError("Corrupted recipient private key envelope.")

        nonce = envelope[:AESGCMService.NONCE_SIZE_BYTES]
        ciphertext_and_tag = envelope[AESGCMService.NONCE_SIZE_BYTES:]
        aad = f"SDPP-RECIPIENT-KEY:{recipient_key.user_id}:v{recipient_key.key_version}".encode("utf-8")

        raw_seed = AESGCMService.decrypt(
            key=rkek,
            nonce=nonce,
            ciphertext_and_tag=ciphertext_and_tag,
            associated_data=aad,
        )
        return mlkem.MLKEM768PrivateKey.from_seed_bytes(raw_seed)

    @classmethod
    def provision_recipient_key(
        cls,
        db: Session,
        user: User,
        actor: User,
        auth_secret: Optional[str] = None,
        supersede_status: str = "REVOKED",
    ) -> RecipientKey:
        """Provisions a new cryptographic key pair for a recipient user.
        
        Lifecycle:
        - If an existing ACTIVE key exists, it transitions to superseded state (REVOKED by default,
          or RETIRED during key rotation) so historical records remain immutable while new distributions
          use the newest ACTIVE key version.
        """
        if not user.is_active:
            raise ValueError("Cannot provision cryptographic key for an inactive user.")

        # Determine next key version
        latest_key = (
            db.query(RecipientKey)
            .filter(RecipientKey.user_id == user.id)
            .order_by(desc(RecipientKey.key_version))
            .first()
        )
        next_version = (latest_key.key_version + 1) if latest_key else 1

        # If previous key was active, mark it superseded
        if latest_key and latest_key.status == "ACTIVE":
            latest_key.status = supersede_status
            if supersede_status == "REVOKED":
                latest_key.revoked_at = datetime.now(timezone.utc)
            db.add(latest_key)

        effective_secret = auth_secret or user.password_hash or "SDP-AUTH-SECRET-DEFAULT"

        # Generate fresh standard ML-KEM-768 key pair
        priv, pub = cls.generate_key_pair()
        pub_b64 = base64.b64encode(MLKEMService.serialize_public_key(pub)).decode("ascii")

        # Protect private key with Argon2id + AES-256-GCM
        protected = KeyProtectionService.protect_private_key(
            priv=priv,
            auth_secret=effective_secret,
            user_id=user.id,
            key_version=next_version,
        )

        now = datetime.now(timezone.utc)
        key_record = RecipientKey(
            user_id=user.id,
            key_version=next_version,
            algorithm=cls.ALGORITHM,
            public_key=pub_b64,
            encrypted_private_key=protected.encrypted_private_key,
            kdf_algorithm=protected.kdf_algorithm,
            kdf_salt=protected.kdf_salt,
            kdf_parameters=json.dumps(protected.kdf_parameters),
            encryption_algorithm=protected.encryption_algorithm,
            encryption_nonce=protected.encryption_nonce,
            status="ACTIVE",
            created_at=now,
            activated_at=now,
        )
        db.add(key_record)
        db.commit()
        db.refresh(key_record)

        AuditService.log_event(
            db=db,
            event_type="RECIPIENT_KEY_PROVISIONED",
            user_id=actor.id,
            metadata={
                "recipient_id": user.id,
                "recipient_username": user.username,
                "key_version": key_record.key_version,
                "algorithm": key_record.algorithm,
            },
        )

        return key_record

    @staticmethod
    def get_active_key(db: Session, user_id: str) -> Optional[RecipientKey]:
        """Retrieves the currently ACTIVE recipient key record for a user.
        
        Only ACTIVE keys may be used for new document distribution.
        """
        return (
            db.query(RecipientKey)
            .filter(RecipientKey.user_id == user_id, RecipientKey.status == "ACTIVE")
            .order_by(desc(RecipientKey.key_version))
            .first()
        )

    @staticmethod
    def revoke_key(db: Session, key_id: str, actor: User) -> RecipientKey:
        """Revokes an existing recipient key. Revoked keys cannot be used for new distributions."""
        key_record = db.query(RecipientKey).filter(RecipientKey.id == key_id).first()
        if not key_record:
            raise ValueError("Recipient key not found.")

        if key_record.status == "REVOKED":
            return key_record

        key_record.status = "REVOKED"
        key_record.revoked_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(key_record)

        AuditService.log_event(
            db=db,
            event_type="RECIPIENT_KEY_REVOKED",
            user_id=actor.id,
            metadata={
                "key_id": key_record.id,
                "recipient_id": key_record.user_id,
                "key_version": key_record.key_version,
                "algorithm": key_record.algorithm,
            },
        )

        return key_record

    @classmethod
    def rotate_key(
        cls,
        db: Session,
        user: User,
        actor: User,
        auth_secret: Optional[str] = None,
    ) -> RecipientKey:
        """Rotates an ML-KEM-768 key pair for a user: old key becomes RETIRED, new key becomes ACTIVE."""
        return cls.provision_recipient_key(
            db=db,
            user=user,
            actor=actor,
            auth_secret=auth_secret,
            supersede_status="RETIRED",
        )

    @staticmethod
    def list_recipient_keys(db: Session, user_id: Optional[str] = None) -> List[RecipientKey]:
        """Lists key records (metadata only) with history preserved."""
        query = db.query(RecipientKey)
        if user_id:
            query = query.filter(RecipientKey.user_id == user_id)
        return query.order_by(desc(RecipientKey.created_at)).all()
