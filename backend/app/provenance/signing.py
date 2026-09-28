"""ML-DSA-65 signing service and key management for cryptographic provenance."""
import json
import base64
import uuid
from datetime import datetime, timezone
from typing import Tuple, Optional
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives import serialization
from app.config.settings import settings
from app.crypto.aes_gcm import AESGCMService
from app.provenance.models import ProvenanceSigningKey
from app.provenance.exceptions import ProvenanceSigningError, ProvenanceKeyError


class ProvenanceSigningService:
    """Standardized ML-DSA-65 post-quantum signing service for cryptographic provenance.
    
    Guarantees:
    - FIPS 204 ML-DSA-65 standardized digital signatures.
    - Dedicated provenance signing identity: strictly isolated from ML-KEM and DEKs.
    - Private key protected at rest via AES-256-GCM authenticated encryption using dedicated server KEK.
    - Key versioning: historical records remain verifiable after key rotation.
    - Exactly one active signing key at any given time.
    """

    ALGORITHM = "ML-DSA-65"

    @classmethod
    def _encrypt_private_key(cls, priv_pem: bytes, key_id: str, key_version: int) -> str:
        """Encrypts the ML-DSA private key PEM using the dedicated provenance KEK and AES-256-GCM."""
        kek = settings.get_provenance_kek_bytes()
        aad = f"PROVENANCE-SIGNING-KEY-v{key_version}:{key_id}".encode("utf-8")
        payload = AESGCMService.encrypt(key=kek, plaintext=priv_pem, associated_data=aad)
        data = {
            "nonce_b64": base64.b64encode(payload.nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(payload.ciphertext_and_tag).decode("ascii"),
        }
        return json.dumps(data)

    @classmethod
    def _decrypt_private_key(cls, encrypted_json: str, key_id: str, key_version: int) -> mldsa.MLDSA65PrivateKey:
        """Decrypts and loads the ML-DSA-65 private key from its encrypted representation."""
        try:
            data = json.loads(encrypted_json)
            nonce = base64.b64decode(data["nonce_b64"])
            ciphertext = base64.b64decode(data["ciphertext_b64"])
            kek = settings.get_provenance_kek_bytes()
            aad = f"PROVENANCE-SIGNING-KEY-v{key_version}:{key_id}".encode("utf-8")
            priv_pem = AESGCMService.decrypt(key=kek, nonce=nonce, ciphertext_and_tag=ciphertext, associated_data=aad)
            priv = serialization.load_pem_private_key(priv_pem, password=None)
            if not isinstance(priv, mldsa.MLDSA65PrivateKey):
                raise ProvenanceSigningError(f"Loaded key is not an MLDSA65PrivateKey: {type(priv)}")
            return priv
        except Exception as e:
            raise ProvenanceSigningError(f"Failed to recover provenance signing private key: {e}")

    @classmethod
    def create_signing_key(cls, db: Session, key_version: int, activate: bool = True) -> ProvenanceSigningKey:
        """Generates and persists a fresh ML-DSA-65 signing key pair."""
        key_id = str(uuid.uuid4())
        priv = mldsa.MLDSA65PrivateKey.generate()
        pub = priv.public_key()

        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        enc_priv_json = cls._encrypt_private_key(priv_pem, key_id, key_version)
        now = datetime.now(timezone.utc)

        signing_key = ProvenanceSigningKey(
            id=key_id,
            key_version=key_version,
            algorithm=cls.ALGORITHM,
            public_key=pub_pem,
            encrypted_private_key=enc_priv_json,
            status="ACTIVE" if activate else "RETIRED",
            created_at=now,
            activated_at=now if activate else None,
            retired_at=None,
        )
        db.add(signing_key)
        db.commit()
        db.refresh(signing_key)
        return signing_key

    @classmethod
    def get_or_create_active_key(cls, db: Session) -> ProvenanceSigningKey:
        """Retrieves the current ACTIVE provenance signing key, generating v1 if none exists."""
        active_key = (
            db.query(ProvenanceSigningKey)
            .filter(ProvenanceSigningKey.status == "ACTIVE")
            .order_by(ProvenanceSigningKey.key_version.desc())
            .first()
        )
        if active_key:
            return active_key

        # If no active key exists, check maximum version
        max_key = (
            db.query(ProvenanceSigningKey)
            .order_by(ProvenanceSigningKey.key_version.desc())
            .first()
        )
        next_ver = (max_key.key_version + 1) if max_key else 1
        return cls.create_signing_key(db, key_version=next_ver, activate=True)

    @classmethod
    def rotate_signing_key(cls, db: Session) -> ProvenanceSigningKey:
        """Rotates the active provenance signing key.
        
        - Retires the current ACTIVE key (setting status='RETIRED', retired_at=now).
        - Generates, encrypts, and activates a new ML-DSA-65 key pair with key_version + 1.
        - Historical public keys remain permanently available for signature verification.
        """
        now = datetime.now(timezone.utc)
        current_active = (
            db.query(ProvenanceSigningKey)
            .filter(ProvenanceSigningKey.status == "ACTIVE")
            .order_by(ProvenanceSigningKey.key_version.desc())
            .first()
        )

        next_version = 1
        if current_active:
            current_active.status = "RETIRED"
            current_active.retired_at = now
            next_version = current_active.key_version + 1

        new_key = cls.create_signing_key(db, key_version=next_version, activate=True)
        return new_key

    @classmethod
    def get_key_by_version(cls, db: Session, key_version: int) -> ProvenanceSigningKey:
        """Retrieves a provenance signing key (active or historical) by version."""
        key = (
            db.query(ProvenanceSigningKey)
            .filter(ProvenanceSigningKey.key_version == key_version)
            .first()
        )
        if not key:
            raise ProvenanceKeyError(f"Provenance signing key version {key_version} not found.")
        return key

    @classmethod
    def sign_canonical_record(
        cls,
        db: Session,
        canonical_bytes: bytes,
        signing_key: Optional[ProvenanceSigningKey] = None,
    ) -> Tuple[str, str, int]:
        """Signs canonical provenance bytes using the active ML-DSA-65 private key.
        
        Args:
            db: Database session.
            canonical_bytes: Deterministic UTF-8 bytes from CanonicalizationService.
            signing_key: Optional explicit key to sign with. If None, uses active key.
            
        Returns:
            Tuple of (signature_b64: str, signature_key_id: str, signature_key_version: int).
        """
        if not canonical_bytes:
            raise ProvenanceSigningError("Cannot sign empty canonical provenance bytes.")

        active_key = signing_key or cls.get_or_create_active_key(db)
        if active_key.status != "ACTIVE":
            raise ProvenanceSigningError(
                f"Cannot sign provenance record with non-active key (status: {active_key.status})."
            )

        priv = cls._decrypt_private_key(active_key.encrypted_private_key, active_key.id, active_key.key_version)
        try:
            raw_sig = priv.sign(canonical_bytes)
            sig_b64 = base64.b64encode(raw_sig).decode("ascii")
            return sig_b64, active_key.id, active_key.key_version
        except Exception as e:
            raise ProvenanceSigningError(f"ML-DSA-65 signing failed: {e}")
