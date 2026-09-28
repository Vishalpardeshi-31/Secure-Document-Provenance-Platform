"""Exceptions for the cryptographic provenance engine."""


class ProvenanceError(Exception):
    """Base exception for cryptographic provenance operations."""
    pass


class ProvenanceSigningError(ProvenanceError):
    """Raised when provenance signing fails."""
    pass


class ProvenanceVerificationError(ProvenanceError):
    """Raised when provenance verification fails or cannot be performed."""
    pass


class CanonicalizationError(ProvenanceError):
    """Raised when canonicalization of a provenance record fails."""
    pass


class ProvenanceKeyError(ProvenanceError):
    """Raised when an active or historical provenance signing key cannot be found or loaded."""
    pass
