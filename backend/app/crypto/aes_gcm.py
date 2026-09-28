"""AES-256-GCM Authenticated Encryption primitive implementation using standard cryptography library."""
import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from app.crypto.models import EncryptedPayload


class AESGCMService:
    """Production-grade AES-256-GCM authenticated cipher service.
    
    Guarantees:
    - 256-bit symmetric keys.
    - 96-bit (12-byte) cryptographically secure nonces generated per operation.
    - Deterministic AAD binding.
    - Fails closed on authentication tag mismatch or malformed ciphertext.
    - Never leaks plaintext or sensitive key material on error.
    """

    KEY_SIZE_BYTES = 32     # AES-256 requires 256 bits (32 bytes)
    NONCE_SIZE_BYTES = 12   # NIST SP 800-38D standard 96-bit IV
    TAG_SIZE_BYTES = 16     # 128-bit authentication tag

    @classmethod
    def generate_key(cls) -> bytes:
        """Generates a cryptographically random 256-bit (32-byte) key using the OS CSPRNG."""
        return secrets.token_bytes(cls.KEY_SIZE_BYTES)

    @classmethod
    def generate_nonce(cls) -> bytes:
        """Generates a cryptographically random 96-bit (12-byte) nonce using the OS CSPRNG."""
        return os.urandom(cls.NONCE_SIZE_BYTES)

    @classmethod
    def encrypt(
        cls,
        key: bytes,
        plaintext: bytes,
        associated_data: bytes,
        nonce: bytes | None = None,
    ) -> EncryptedPayload:
        """Encrypts plaintext with AES-256-GCM and authenticates associated data.
        
        Args:
            key: Exactly 32 bytes (256 bits).
            plaintext: Plaintext bytes to encrypt.
            associated_data: Additional authenticated data (AAD).
            nonce: Optional 12-byte nonce. If None, freshly generated from CSPRNG.
            
        Returns:
            EncryptedPayload containing the 12-byte nonce and (ciphertext + 16-byte auth tag).
        """
        if len(key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"AES-256 key must be exactly {cls.KEY_SIZE_BYTES} bytes. Received {len(key)} bytes.")
        
        effective_nonce = nonce if nonce is not None else cls.generate_nonce()
        if len(effective_nonce) != cls.NONCE_SIZE_BYTES:
            raise ValueError(f"AES-GCM nonce must be exactly {cls.NONCE_SIZE_BYTES} bytes. Received {len(effective_nonce)} bytes.")

        aesgcm = AESGCM(key)
        # encrypt(nonce, data, associated_data) returns ciphertext + 16-byte tag
        ciphertext_and_tag = aesgcm.encrypt(effective_nonce, plaintext, associated_data)

        return EncryptedPayload(nonce=effective_nonce, ciphertext_and_tag=ciphertext_and_tag)

    @classmethod
    def decrypt(
        cls,
        key: bytes,
        nonce: bytes,
        ciphertext_and_tag: bytes,
        associated_data: bytes,
    ) -> bytes:
        """Authenticates and decrypts AES-256-GCM ciphertext.
        
        Fails closed on any corruption, modified nonce, modified AAD, or tag mismatch.
        
        Args:
            key: Exactly 32 bytes.
            nonce: Exactly 12 bytes.
            ciphertext_and_tag: Ciphertext concatenated with 16-byte auth tag.
            associated_data: Additional authenticated data (AAD).
            
        Returns:
            Decrypted plaintext bytes.
            
        Raises:
            ValueError: If authentication fails, parameters are invalid, or data has been tampered with.
        """
        if len(key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"AES-256 key must be exactly {cls.KEY_SIZE_BYTES} bytes. Received {len(key)} bytes.")
        if len(nonce) != cls.NONCE_SIZE_BYTES:
            raise ValueError(f"AES-GCM nonce must be exactly {cls.NONCE_SIZE_BYTES} bytes. Received {len(nonce)} bytes.")
        if len(ciphertext_and_tag) < cls.TAG_SIZE_BYTES:
            raise ValueError("Ciphertext is too short to contain a valid authentication tag.")

        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)
        except InvalidTag:
            raise ValueError("Cryptographic authentication failed: ciphertext, nonce, tag, or AAD has been tampered with.")
        except Exception:
            raise ValueError("Cryptographic authentication failed.")
