"""Provenance hashing service for calculating deterministic SHA-256 hashes."""
import hashlib
from app.provenance.exceptions import CanonicalizationError


class ProvenanceHashService:
    """Computes deterministic cryptographic hashes over canonical provenance records."""

    @staticmethod
    def hash_canonical_record(canonical_bytes: bytes) -> str:
        """Computes SHA-256 of the canonical provenance bytes.
        
        Args:
            canonical_bytes: The deterministic UTF-8 bytes from CanonicalizationService.
            
        Returns:
            str: 64-character lowercase hexadecimal SHA-256 hash.
        """
        if not canonical_bytes:
            raise CanonicalizationError("Cannot hash empty canonical provenance record.")

        return hashlib.sha256(canonical_bytes).hexdigest().lower()
