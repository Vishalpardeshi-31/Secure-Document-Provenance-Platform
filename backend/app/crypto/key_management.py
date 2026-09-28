"""Key management abstraction separating legacy server-side envelopes from modern per-recipient post-quantum wrapping."""
import base64
from typing import Optional, Union
from cryptography.hazmat.primitives.asymmetric import mlkem
from app.config.settings import settings
from app.crypto.aes_gcm import AESGCMService
from app.crypto.ml_kem import MLKEMService
from app.crypto.hkdf import HKDFService
from app.crypto.aad import build_dek_wrap_kdf_info, build_dek_wrap_aad
from app.crypto.models import WrappedDEKEnvelope


class LegacyServerEnvelopeKeyManagement:
    """Phase 3 backward compatibility: wraps/unwraps DEK using server-side master KEK.
    
    STRICTLY FOR HISTORICAL DOCUMENTS (key_management_version = 1).
    New documents must NEVER use this path.
    """
    LEGACY_AAD = b"SDPP-KEY-ENVELOPE-V1"

    @classmethod
    def wrap_dek(cls, dek: bytes, custom_kek: Optional[bytes] = None) -> str:
        """Wraps a 256-bit DEK inside a server-side AES-256-GCM envelope."""
        kek = custom_kek if custom_kek is not None else settings.get_kek_bytes()
        if len(kek) != 32:
            raise ValueError(f"Server KEK must be exactly 32 bytes. Found {len(kek)} bytes.")

        nonce = AESGCMService.generate_nonce()
        encrypted = AESGCMService.encrypt(
            key=kek,
            plaintext=dek,
            associated_data=cls.LEGACY_AAD,
            nonce=nonce,
        )
        envelope_bytes = nonce + encrypted.ciphertext_and_tag
        return base64.b64encode(envelope_bytes).decode("ascii")

    @classmethod
    def unwrap_dek(cls, wrapped_dek_b64: str, custom_kek: Optional[bytes] = None) -> bytes:
        """Unwraps a 256-bit DEK from a server-side envelope for Phase 3 documents."""
        kek = custom_kek if custom_kek is not None else settings.get_kek_bytes()
        envelope_bytes = base64.b64decode(wrapped_dek_b64)
        if len(envelope_bytes) < AESGCMService.NONCE_SIZE_BYTES + AESGCMService.TAG_SIZE_BYTES:
            raise ValueError("Invalid legacy key envelope length.")

        nonce = envelope_bytes[:AESGCMService.NONCE_SIZE_BYTES]
        ciphertext_and_tag = envelope_bytes[AESGCMService.NONCE_SIZE_BYTES:]

        return AESGCMService.decrypt(
            key=kek,
            nonce=nonce,
            ciphertext_and_tag=ciphertext_and_tag,
            associated_data=cls.LEGACY_AAD,
        )


class RecipientWrappedKeyManagement:
    """Production key management: ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM.
    
    Architecture:
    One document -> one random 256-bit DEK -> one ciphertext -> independently wrapped DEK per recipient.
    
    Per-recipient flow:
    1. ML-KEM-768.Encapsulate(recipient_public_key) -> (shared_secret, kem_ciphertext)
    2. HKDF-SHA-256(IKM=shared_secret, info=build_dek_wrap_kdf_info(...)) -> recipient KEK (32 bytes)
    3. AES-256-GCM.Encrypt(key=recipient KEK, plaintext=DEK, nonce=fresh 12 bytes, AAD=build_dek_wrap_aad(...))
    """

    PROTOCOL_VERSION = "SDP-CRYPTO-V2"
    KEM_ALGORITHM = "ML-KEM-768"
    KDF_ALGORITHM = "HKDF-SHA-256"
    WRAP_ALGORITHM = "AES-256-GCM"
    KDF_INFO_VERSION = "SDP-DEK-WRAP-v1"

    @classmethod
    def wrap_dek_for_recipient(
        cls,
        dek: bytes,
        recipient_public_key_bytes: bytes,
        document_id: str,
        document_version_id: Union[str, int],
        recipient_user_id: str,
        recipient_key_id: str,
        recipient_key_version: int,
        protocol_version: str = PROTOCOL_VERSION,
    ) -> WrappedDEKEnvelope:
        """Independently encapsulates and wraps the document DEK for an authorized recipient."""
        if len(dek) != 32:
            raise ValueError("Document DEK must be exactly 32 bytes.")

        # Step A: ML-KEM encapsulation
        shared_secret, kem_ciphertext = MLKEMService.encapsulate(recipient_public_key_bytes)

        # Step B: HKDF-SHA-256 key derivation
        kdf_info = build_dek_wrap_kdf_info(
            protocol_version=protocol_version,
            document_id=document_id,
            document_version_id=document_version_id,
            recipient_user_id=recipient_user_id,
            recipient_key_id=recipient_key_id,
            recipient_key_version=recipient_key_version,
            kdf_info_version=cls.KDF_INFO_VERSION,
        )
        recipient_kek = HKDFService.derive_kek(
            shared_secret=shared_secret,
            info=kdf_info,
        )

        # Step C: AES-256-GCM wrap DEK
        wrap_nonce = AESGCMService.generate_nonce()
        wrap_aad = build_dek_wrap_aad(
            protocol_version=protocol_version,
            document_id=document_id,
            document_version_id=document_version_id,
            recipient_user_id=recipient_user_id,
            recipient_key_id=recipient_key_id,
            recipient_key_version=recipient_key_version,
        )
        encrypted_dek = AESGCMService.encrypt(
            key=recipient_kek,
            plaintext=dek,
            associated_data=wrap_aad,
            nonce=wrap_nonce,
        )

        return WrappedDEKEnvelope(
            kem_ciphertext=kem_ciphertext,
            wrap_nonce=wrap_nonce,
            wrapped_dek=encrypted_dek.ciphertext_and_tag,
            recipient_key_id=recipient_key_id,
            recipient_key_version=recipient_key_version,
            kem_algorithm=cls.KEM_ALGORITHM,
            kdf_algorithm=cls.KDF_ALGORITHM,
            kdf_info_version=cls.KDF_INFO_VERSION,
            wrap_algorithm=cls.WRAP_ALGORITHM,
            protocol_version=protocol_version,
        )

    @classmethod
    def unwrap_dek_for_recipient(
        cls,
        envelope: WrappedDEKEnvelope,
        recipient_priv: mlkem.MLKEM768PrivateKey,
        document_id: str,
        document_version_id: Union[str, int],
        recipient_user_id: str,
    ) -> bytes:
        """Unwraps the document DEK using the recipient's ML-KEM private key and envelope metadata."""
        # Step A: ML-KEM decapsulation
        shared_secret = MLKEMService.decapsulate(
            private_key=recipient_priv,
            kem_ciphertext=envelope.kem_ciphertext,
        )

        # Step B: HKDF-SHA-256 key derivation with canonical context
        kdf_info = build_dek_wrap_kdf_info(
            protocol_version=envelope.protocol_version,
            document_id=document_id,
            document_version_id=document_version_id,
            recipient_user_id=recipient_user_id,
            recipient_key_id=envelope.recipient_key_id,
            recipient_key_version=envelope.recipient_key_version,
            kdf_info_version=envelope.kdf_info_version,
        )
        recipient_kek = HKDFService.derive_kek(
            shared_secret=shared_secret,
            info=kdf_info,
        )

        # Step C: AES-256-GCM unwrap with canonical AAD
        wrap_aad = build_dek_wrap_aad(
            protocol_version=envelope.protocol_version,
            document_id=document_id,
            document_version_id=document_version_id,
            recipient_user_id=recipient_user_id,
            recipient_key_id=envelope.recipient_key_id,
            recipient_key_version=envelope.recipient_key_version,
        )

        try:
            return AESGCMService.decrypt(
                key=recipient_kek,
                nonce=envelope.wrap_nonce,
                ciphertext_and_tag=envelope.wrapped_dek,
                associated_data=wrap_aad,
            )
        except Exception:
            raise ValueError("Cryptographic unwrap failed: invalid recipient key or tampered distribution envelope.")


class KeyManagementService:
    """Unified cryptographic key management service enforcing strict version dispatch."""

    CURRENT_VERSION = 2
    PROTOCOL_VERSION = "SDP-CRYPTO-V2"

    legacy = LegacyServerEnvelopeKeyManagement
    recipient = RecipientWrappedKeyManagement

    @classmethod
    def get_server_kek(cls) -> bytes:
        return settings.get_kek_bytes()

    @classmethod
    def wrap_dek(cls, dek: bytes, custom_kek: Optional[bytes] = None) -> str:
        """Legacy helper for Phase 3 server envelope."""
        return cls.legacy.wrap_dek(dek, custom_kek)

    @classmethod
    def unwrap_dek(cls, wrapped_dek_b64: str, custom_kek: Optional[bytes] = None) -> bytes:
        """Legacy helper for Phase 3 server envelope."""
        return cls.legacy.unwrap_dek(wrapped_dek_b64, custom_kek)
