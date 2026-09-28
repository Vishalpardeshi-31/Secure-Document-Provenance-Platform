"""Forensic Fingerprinting Preparation Interface (Phase 11 Extension Point).

This module defines the context contract and interface for future recipient-specific
invisible forensic fingerprinting without implementing fake watermarks or simulations.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any


@dataclass(frozen=True)
class ForensicFingerprintContext:
    """Carries complete viewer/provenance session context for downstream forensic fingerprinting."""
    document_id: str
    document_version_id: str
    user_id: str
    recipient_identity: str
    decryption_session_id: str
    viewer_session_id: str
    provenance_event_id: Optional[str]
    timestamp: datetime
    rendering_context: Optional[Dict[str, Any]] = None


class ForensicFingerprintProvider:
    """Extension interface for forensic watermark/fingerprint embedding.
    In Phase 11, returns plaintext unmodified without fake watermarking.
    """

    @classmethod
    def prepare_document_rendering(
        cls,
        content: bytes,
        mime_type: str,
        context: ForensicFingerprintContext,
    ) -> bytes:
        """Extension point called prior to delivery. Returns unmodified content in Phase 11."""
        return content
