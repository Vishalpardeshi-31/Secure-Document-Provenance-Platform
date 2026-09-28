"""Key Management Service bridging the cryptographic subsystem with application workflows."""
import base64
from typing import Tuple, Optional, Union
from cryptography.hazmat.primitives.asymmetric import mlkem

from app.config.settings import settings
from app.crypto.aes_gcm import AESGCMService
from app.crypto.ml_kem import MLKEMService
from app.crypto.hkdf import HKDFService
from app.crypto.aad import build_dek_wrap_kdf_info, build_dek_wrap_aad
from app.crypto.key_management import (
    LegacyServerEnvelopeKeyManagement,
    RecipientWrappedKeyManagement,
)


class KeyManagementService:
    """Manages document key envelope encryption and multi-recipient key wrapping.
    
    Architecture:
    - LegacyServerEnvelopeKeyManagement (Phase 3 envelope) for historical backward compatibility.
    - RecipientWrappedKeyManagement (Phase 4/5/6) for per-recipient post-quantum DEK wrapping:
      ML-KEM-768 encapsulation -> HKDF-SHA256 -> AES-256-GCM.
    """

    RECIPIENT_ALGORITHM = "ML-KEM-768+HKDF-SHA256+AES-256-GCM"
    CURRENT_VERSION = 2
    PROTOCOL_VERSION = "SDP-CRYPTO-V2"

    legacy = LegacyServerEnvelopeKeyManagement
    recipient = RecipientWrappedKeyManagement

    @staticmethod
    def get_server_kek() -> bytes:
        """Retrieves the verified 32-byte server master KEK from application settings."""
        return settings.get_kek_bytes()

    @classmethod
    def wrap_dek(cls, dek: bytes, custom_kek: Optional[bytes] = None) -> str:
        """Wraps a 256-bit DEK using server-side KEK envelope for Phase 3 backward compatibility."""
        return cls.legacy.wrap_dek(dek, custom_kek)

    @classmethod
    def unwrap_dek(cls, wrapped_dek_b64: str, custom_kek: Optional[bytes] = None) -> bytes:
        """Unwraps a server-side KEK envelope for Phase 3 documents."""
        return cls.legacy.unwrap_dek(wrapped_dek_b64, custom_kek)

    @classmethod
    def wrap_dek_for_recipient(
        cls,
        dek: bytes,
        recipient_public_key_b64: str,
        document_id: Optional[str] = None,
        document_version_id: Union[str, int] = "1",
        recipient_user_id: Optional[str] = None,
        recipient_key_id: Optional[str] = None,
        recipient_key_version: int = 1,
        protocol_version: str = "SDP-CRYPTO-V2",
    ) -> Tuple[str, str, str, str]:
        """Cryptographically encapsulates and wraps the document DEK for a specific recipient.
        
        Binds to canonical AAD and HKDF info when document and recipient identities are provided.
        """
        if len(dek) != 32:
            raise ValueError(f"DEK must be exactly 32 bytes (256 bits). Found {len(dek)} bytes.")

        raw_pub = base64.b64decode(recipient_public_key_b64)
        pub = MLKEMService.deserialize_public_key(raw_pub)

        # ML-KEM-768 encapsulation
        shared_secret, kem_ciphertext = pub.encapsulate()

        # Build contextual or legacy info
        if document_id and recipient_user_id:
            effective_key_id = recipient_key_id or "default_key"
            kdf_info = build_dek_wrap_kdf_info(
                protocol_version=protocol_version,
                document_id=document_id,
                document_version_id=document_version_id,
                recipient_user_id=recipient_user_id,
                recipient_key_id=effective_key_id,
                recipient_key_version=recipient_key_version,
            )
            wrap_aad = build_dek_wrap_aad(
                protocol_version=protocol_version,
                document_id=document_id,
                document_version_id=document_version_id,
                recipient_user_id=recipient_user_id,
                recipient_key_id=effective_key_id,
                recipient_key_version=recipient_key_version,
            )
        else:
            kdf_info = b"SDPP-RECIPIENT-DEK-WRAP-V1"
            wrap_aad = b"SDPP-RECIPIENT-DEK-ENVELOPE-V1"

        # HKDF-SHA-256 KEK derivation
        derived_kek = HKDFService.derive_kek(shared_secret=shared_secret, info=kdf_info)

        # AES-256-GCM DEK wrap
        wrap_nonce = AESGCMService.generate_nonce()
        encrypted = AESGCMService.encrypt(
            key=derived_kek,
            plaintext=dek,
            associated_data=wrap_aad,
            nonce=wrap_nonce,
        )

        return (
            base64.b64encode(kem_ciphertext).decode("ascii"),
            base64.b64encode(wrap_nonce).decode("ascii"),
            base64.b64encode(encrypted.ciphertext_and_tag).decode("ascii"),
            cls.RECIPIENT_ALGORITHM,
        )

    @classmethod
    def unwrap_dek_for_recipient(
        cls,
        encapsulated_key_b64: str,
        nonce_b64: str,
        wrapped_dek_b64: str,
        recipient_priv: mlkem.MLKEM768PrivateKey,
        document_id: Optional[str] = None,
        document_version_id: Union[str, int] = "1",
        recipient_user_id: Optional[str] = None,
        recipient_key_id: Optional[str] = None,
        recipient_key_version: int = 1,
        protocol_version: str = "SDP-CRYPTO-V2",
    ) -> bytes:
        """INTERNAL ONLY: Decapsulates and unwraps the document DEK using recipient's private key.
        
        Attempts canonical AAD verification, with fallback to legacy Phase 4 envelope format.
        """
        kem_ciphertext = base64.b64decode(encapsulated_key_b64)
        wrap_nonce = base64.b64decode(nonce_b64)
        wrapped_dek = base64.b64decode(wrapped_dek_b64)

        # ML-KEM-768 decapsulation
        shared_secret = MLKEMService.decapsulate(recipient_priv, kem_ciphertext)

        # Try canonical contextual KEK derivation & unwrap first if context is provided
        if document_id and recipient_user_id:
            effective_key_id = recipient_key_id or "default_key"
            kdf_info = build_dek_wrap_kdf_info(
                protocol_version=protocol_version,
                document_id=document_id,
                document_version_id=document_version_id,
                recipient_user_id=recipient_user_id,
                recipient_key_id=effective_key_id,
                recipient_key_version=recipient_key_version,
            )
            wrap_aad = build_dek_wrap_aad(
                protocol_version=protocol_version,
                document_id=document_id,
                document_version_id=document_version_id,
                recipient_user_id=recipient_user_id,
                recipient_key_id=effective_key_id,
                recipient_key_version=recipient_key_version,
            )
            derived_kek = HKDFService.derive_kek(shared_secret=shared_secret, info=kdf_info)
            try:
                return AESGCMService.decrypt(
                    key=derived_kek,
                    nonce=wrap_nonce,
                    ciphertext_and_tag=wrapped_dek,
                    associated_data=wrap_aad,
                )
            except Exception:
                # If contextual decryption fails, try legacy Phase 4 format before failing closed
                pass

        # Legacy Phase 4 fallback
        legacy_kek = HKDFService.derive_kek(shared_secret=shared_secret, info=b"SDPP-RECIPIENT-DEK-WRAP-V1")
        return AESGCMService.decrypt(
            key=legacy_kek,
            nonce=wrap_nonce,
            ciphertext_and_tag=wrapped_dek,
            associated_data=b"SDPP-RECIPIENT-DEK-ENVELOPE-V1",
        )
