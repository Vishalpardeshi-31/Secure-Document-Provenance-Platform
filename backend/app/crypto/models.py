"""Data models and transfer objects for the cryptographic subsystem."""
from dataclasses import dataclass, field
from typing import Dict, Any, Optional


@dataclass(frozen=True)
class EncryptedPayload:
    """Represents the output of an authenticated encryption operation."""
    nonce: bytes
    ciphertext_and_tag: bytes


@dataclass(frozen=True)
class WrappedDEKEnvelope:
    """Cryptographic envelope holding a document DEK wrapped for a specific recipient.
    
    Contains:
    - ML-KEM-768 ciphertext (decapsulated by recipient's private key)
    - HKDF context parameters
    - AES-256-GCM wrapped DEK + tag
    - 12-byte wrap nonce
    - Protocol & Key versioning metadata
    """
    kem_ciphertext: bytes
    wrap_nonce: bytes
    wrapped_dek: bytes
    recipient_key_id: str
    recipient_key_version: int
    kem_algorithm: str = "ML-KEM-768"
    kdf_algorithm: str = "HKDF-SHA-256"
    kdf_info_version: str = "SDP-DEK-WRAP-v1"
    wrap_algorithm: str = "AES-256-GCM"
    protocol_version: str = "SDP-CRYPTO-V2"


@dataclass(frozen=True)
class ProtectedPrivateKeyMaterial:
    """Recipient private key material protected at rest using Argon2id + AES-256-GCM.
    
    Never stores plaintext private key, derived KEK, or shared secret.
    """
    encrypted_private_key: str  # Base64-encoded AES-GCM ciphertext + tag
    kdf_algorithm: str = "Argon2id"
    kdf_salt: str = ""          # Hex-encoded 16-byte random salt
    kdf_parameters: Dict[str, Any] = field(default_factory=dict)
    encryption_algorithm: str = "AES-256-GCM"
    encryption_nonce: str = ""  # Hex-encoded 12-byte random nonce
    key_version: int = 1


@dataclass(frozen=True)
class CryptoSelfCheckResult:
    """Result of startup cryptographic primitive verification."""
    is_valid: bool
    verified_algorithms: Dict[str, str]
    error_message: Optional[str] = None
