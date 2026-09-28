"""HKDF-SHA-256 Key Derivation Function (RFC 5869) using standard cryptography library."""
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class HKDFService:
    """Production-grade HKDF-SHA-256 key derivation service.
    
    Extracts and expands high-entropy cryptographic keys bound to application contexts.
    """

    DERIVED_KEY_SIZE_BYTES = 32  # 256 bits

    @classmethod
    def derive_kek(
        cls,
        shared_secret: bytes,
        info: bytes,
        salt: Optional[bytes] = None,
        length: int = DERIVED_KEY_SIZE_BYTES,
    ) -> bytes:
        """Derives a recipient symmetric Key-Encryption Key (KEK) using HKDF-SHA-256.
        
        Args:
            shared_secret: Input Key Material (IKM) from ML-KEM-768 encapsulation.
            info: Canonical context information binding recipient, document, and key version.
            salt: Optional salt value. If None, HKDF uses a string of zeros per RFC 5869.
            length: Number of bytes to derive (default: 32 bytes).
            
        Returns:
            Derived 32-byte symmetric KEK.
        """
        if not shared_secret:
            raise ValueError("Input Key Material (shared_secret) must not be empty.")
        if not info:
            raise ValueError("HKDF context info must not be empty.")
        if length != cls.DERIVED_KEY_SIZE_BYTES:
            raise ValueError(f"Derived key length must be exactly {cls.DERIVED_KEY_SIZE_BYTES} bytes.")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(shared_secret)
