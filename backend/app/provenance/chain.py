"""Deterministic canonicalization and hashing for the append-only provenance chain."""
import hashlib
from typing import Dict, Any
from app.provenance.exceptions import CanonicalizationError


class ProvenanceChainService:
    """Canonical chain representation and SHA-256 chain hash computation.
    
    Security Guarantee:
    - Fixed field ordering: CHAIN_ID, CHAIN_SEQUENCE, PREVIOUS_RECORD_HASH, CANONICAL_RECORD_HASH, EVENT_ID.
    - Explicit UTF-8 length-delimited encoding: <FIELD>:<LEN>:<VAL>\n.
    - No locale dependence, no floating-point values, no ambiguous serialization.
    - Mathematically binds the current event to the immutable chain history.
    """

    CHAIN_PROTOCOL_VERSION = "PROVENANCE-CHAIN-V1"
    CANONICAL_CHAIN_FIELDS = [
        "CHAIN_ID",
        "CHAIN_SEQUENCE",
        "PREVIOUS_RECORD_HASH",
        "CANONICAL_RECORD_HASH",
        "EVENT_ID",
    ]

    @classmethod
    def build_chain_payload(
        cls,
        chain_id: str,
        chain_sequence: int,
        previous_record_hash: str,
        canonical_record_hash: str,
        event_id: str,
        protocol_version: str = "PROVENANCE-CHAIN-V1",
    ) -> bytes:
        """Constructs the deterministic canonical bytes for a chain link."""
        if not chain_id or not isinstance(chain_id, str):
            raise CanonicalizationError("chain_id must be a non-empty string.")

        if not isinstance(chain_sequence, int) or chain_sequence < 0:
            raise CanonicalizationError("chain_sequence must be a non-negative integer.")

        if not previous_record_hash or len(previous_record_hash) != 64:
            raise CanonicalizationError(
                f"previous_record_hash must be a 64-character hex string, got: {previous_record_hash!r}"
            )

        if not canonical_record_hash or len(canonical_record_hash) != 64:
            raise CanonicalizationError(
                f"canonical_record_hash must be a 64-character hex string, got: {canonical_record_hash!r}"
            )

        if not event_id or not isinstance(event_id, str):
            raise CanonicalizationError("event_id must be a non-empty string.")

        values: Dict[str, str] = {
            "CHAIN_ID": chain_id.strip(),
            "CHAIN_SEQUENCE": str(chain_sequence),
            "PREVIOUS_RECORD_HASH": previous_record_hash.strip().lower(),
            "CANONICAL_RECORD_HASH": canonical_record_hash.strip().lower(),
            "EVENT_ID": event_id.strip(),
        }

        canonical_lines = [f"{protocol_version}\n".encode("utf-8")]
        for field in cls.CANONICAL_CHAIN_FIELDS:
            val_bytes = values[field].encode("utf-8")
            line = f"{field}:{len(val_bytes)}:".encode("utf-8") + val_bytes + b"\n"
            canonical_lines.append(line)

        return b"".join(canonical_lines)

    @classmethod
    def calculate_chain_hash(
        cls,
        chain_id: str,
        chain_sequence: int,
        previous_record_hash: str,
        canonical_record_hash: str,
        event_id: str,
        protocol_version: str = "PROVENANCE-CHAIN-V1",
    ) -> str:
        """Calculates the 64-character lowercase hexadecimal SHA-256 chain hash."""
        payload = cls.build_chain_payload(
            chain_id=chain_id,
            chain_sequence=chain_sequence,
            previous_record_hash=previous_record_hash,
            canonical_record_hash=canonical_record_hash,
            event_id=event_id,
            protocol_version=protocol_version,
        )
        return hashlib.sha256(payload).hexdigest().lower()
