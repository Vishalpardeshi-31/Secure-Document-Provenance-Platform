"""Cryptographic hashing and constant-time integrity verification using SHA-256."""
import hashlib
import hmac


class HashService:
    """Standard SHA-256 integrity and provenance hashing service."""

    @staticmethod
    def sha256_hex(data: bytes) -> str:
        """Calculates the lowercase hexadecimal SHA-256 digest of input bytes."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def sha256_bytes(data: bytes) -> bytes:
        """Calculates the raw 32-byte SHA-256 digest of input bytes."""
        return hashlib.sha256(data).digest()

    @staticmethod
    def verify_sha256(data: bytes, expected_hex: str) -> bool:
        """Verifies data matches expected SHA-256 digest using constant-time comparison."""
        actual_hex = hashlib.sha256(data).hexdigest()
        return hmac.compare_digest(actual_hex.lower(), expected_hex.lower())
