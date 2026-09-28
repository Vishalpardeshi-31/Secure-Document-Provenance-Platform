import os
import hashlib
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class CryptoService:
    """Cryptographic service for symmetric AES-256-GCM file and key envelope operations."""

    DEK_SIZE_BYTES = 32  # 256 bits
    NONCE_SIZE_BYTES = 12  # 96 bits for AES-GCM
    TAG_SIZE_BYTES = 16  # 128 bits authentication tag (automatically appended by AESGCM)

    @staticmethod
    def generate_dek() -> bytes:
        """Generates a cryptographically random 256-bit (32-byte) Data Encryption Key (DEK)."""
        return os.urandom(CryptoService.DEK_SIZE_BYTES)

    @staticmethod
    def generate_nonce() -> bytes:
        """Generates a unique 96-bit (12-byte) initialization vector/nonce for AES-GCM."""
        return os.urandom(CryptoService.NONCE_SIZE_BYTES)

    @staticmethod
    def calculate_sha256(data: bytes) -> str:
        """Calculates the SHA-256 digest of binary data as a lowercase hex string."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def encrypt_bytes(
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Encrypts binary data using AES-256-GCM with authentication tag appended.
        
        Args:
            key: 32-byte AES-256 key
            nonce: 12-byte unique GCM nonce
            plaintext: Raw bytes to encrypt
            associated_data: Optional authenticated additional data (AAD)
            
        Returns:
            Ciphertext with 16-byte authentication tag appended.
        """
        if len(key) != CryptoService.DEK_SIZE_BYTES:
            raise ValueError(f"AES-256 requires a 32-byte key. Received {len(key)} bytes.")
        if len(nonce) != CryptoService.NONCE_SIZE_BYTES:
            raise ValueError(f"AES-GCM requires a 12-byte nonce. Received {len(nonce)} bytes.")

        aesgcm = AESGCM(key)
        return aesgcm.encrypt(nonce, plaintext, associated_data)

    @staticmethod
    def decrypt_bytes(
        key: bytes,
        nonce: bytes,
        ciphertext_and_tag: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Internal decryption and authentication verification routine.
        NOTE: In accordance with Phase 3 scope, this is internal only and NOT exposed via API.
        
        Raises:
            ValueError: If key/nonce are invalid sizes or tag verification fails.
        """
        if len(key) != CryptoService.DEK_SIZE_BYTES:
            raise ValueError(f"AES-256 requires a 32-byte key. Received {len(key)} bytes.")
        if len(nonce) != CryptoService.NONCE_SIZE_BYTES:
            raise ValueError(f"AES-GCM requires a 12-byte nonce. Received {len(nonce)} bytes.")
        if len(ciphertext_and_tag) < CryptoService.TAG_SIZE_BYTES:
            raise ValueError("Ciphertext is shorter than minimum authentication tag length.")

        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)
        except InvalidTag:
            raise ValueError("Cryptographic authentication failed: Ciphertext or tag has been tampered with.")
