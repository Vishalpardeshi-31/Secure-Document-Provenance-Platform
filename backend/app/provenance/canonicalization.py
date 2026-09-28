"""Deterministic canonicalization service for provenance records.

Canonicalization Specification:
--------------------------------
1. Encoding: Strict UTF-8 throughout.
2. Delimiter & Length Rules:
   Every field is formatted as:
     <FIELD_NAME>:<BYTE_LENGTH>:<VALUE>\n
   where BYTE_LENGTH is the ASCII decimal count of bytes in <VALUE>.
3. Null Representations:
   Null/None values are unambiguously represented as zero-length:
     <FIELD_NAME>:0:\n
4. Numeric Values:
   Integers are formatted as base-10 ASCII digits without leading zeros.
   Floating-point numbers are prohibited.
5. Timestamps:
   Normalized to RFC 3339 / ISO 8601 UTC representation:
     YYYY-MM-DDTHH:MM:SSZ
6. Hexadecimal Hashes:
   All SHA-256 hashes are normalized to lowercase 64-character hex strings.
7. Header:
   Begins with explicit protocol version identifier line:
     PROVENANCE-V1\n
"""
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from app.provenance.exceptions import CanonicalizationError


class CanonicalizationService:
    """Provides deterministic byte canonicalization for cryptographic provenance records."""

    PROTOCOL_VERSION = "PROVENANCE-V1"

    # Strict, immutable field ordering for canonical representation
    CANONICAL_FIELD_ORDER = [
        "PROTOCOL_VERSION",
        "EVENT_ID",
        "DOCUMENT_ID",
        "DOCUMENT_VERSION_ID",
        "USER_ID",
        "RECIPIENT_KEY_ID",
        "RECIPIENT_KEY_VERSION",
        "DEVICE_ID",
        "DECRYPTION_SESSION_ID",
        "POLICY_ID",
        "POLICY_VERSION",
        "ACCESS_TYPE",
        "APPROVAL_REQUEST_ID",
        "EMERGENCY_ACCESS_REQUEST_ID",
        "DOCUMENT_PLAINTEXT_SHA256",
        "DOCUMENT_CIPHERTEXT_SHA256",
        "EVENT_TIMESTAMP",
    ]

    @classmethod
    def normalize_timestamp(cls, ts: Any) -> str:
        """Normalizes any datetime or string timestamp to ISO 8601 UTC (YYYY-MM-DDTHH:MM:SSZ)."""
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                dt_utc = ts.replace(tzinfo=timezone.utc)
            else:
                dt_utc = ts.astimezone(timezone.utc)
            return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        elif isinstance(ts, str):
            clean = ts.strip()
            # If standard trailing Z or +00:00:
            try:
                dt = datetime.fromisoformat(clean.replace("Z", "+00:00"))
                dt_utc = dt.astimezone(timezone.utc)
                return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception as e:
                raise CanonicalizationError(f"Invalid timestamp format '{ts}': {e}")
        else:
            raise CanonicalizationError(f"Unsupported timestamp type: {type(ts)}")

    @classmethod
    def canonicalize_provenance_record(
        cls,
        *,
        event_id: str,
        document_id: str,
        document_version_id: str,
        user_id: str,
        recipient_key_id: Optional[str],
        recipient_key_version: Optional[int],
        device_id: Optional[str],
        decryption_session_id: str,
        policy_id: str,
        policy_version: int,
        access_type: str,
        approval_request_id: Optional[str],
        emergency_access_request_id: Optional[str],
        document_plaintext_sha256: str,
        document_ciphertext_sha256: str,
        event_timestamp: Any,
        protocol_version: str = PROTOCOL_VERSION,
    ) -> bytes:
        """Generates the deterministic canonical bytes representation for a provenance record.
        
        Returns:
            bytes: The canonicalized record in strict UTF-8.
        """
        # Validate required identifiers
        if not event_id or not document_id or not user_id or not decryption_session_id or not policy_id:
            raise CanonicalizationError("Required provenance identifier is missing or empty.")

        # Normalize values
        norm_ts = cls.normalize_timestamp(event_timestamp)
        norm_pt_sha = str(document_plaintext_sha256).strip().lower()
        norm_ct_sha = str(document_ciphertext_sha256).strip().lower()

        if len(norm_pt_sha) != 64 or len(norm_ct_sha) != 64:
            raise CanonicalizationError("Document hashes must be exactly 64 hexadecimal characters.")

        # Dictionary of normalized values
        values: Dict[str, str] = {
            "PROTOCOL_VERSION": str(protocol_version).strip(),
            "EVENT_ID": str(event_id).strip(),
            "DOCUMENT_ID": str(document_id).strip(),
            "DOCUMENT_VERSION_ID": str(document_version_id).strip(),
            "USER_ID": str(user_id).strip(),
            "RECIPIENT_KEY_ID": str(recipient_key_id).strip() if recipient_key_id else "",
            "RECIPIENT_KEY_VERSION": str(int(recipient_key_version)) if recipient_key_version is not None else "",
            "DEVICE_ID": str(device_id).strip() if device_id else "",
            "DECRYPTION_SESSION_ID": str(decryption_session_id).strip(),
            "POLICY_ID": str(policy_id).strip(),
            "POLICY_VERSION": str(int(policy_version)),
            "ACCESS_TYPE": str(access_type).strip().upper(),
            "APPROVAL_REQUEST_ID": str(approval_request_id).strip() if approval_request_id else "",
            "EMERGENCY_ACCESS_REQUEST_ID": str(emergency_access_request_id).strip() if emergency_access_request_id else "",
            "DOCUMENT_PLAINTEXT_SHA256": norm_pt_sha,
            "DOCUMENT_CIPHERTEXT_SHA256": norm_ct_sha,
            "EVENT_TIMESTAMP": norm_ts,
        }

        # Build canonical lines
        canonical_lines = [f"{protocol_version}\n".encode("utf-8")]

        for field_name in cls.CANONICAL_FIELD_ORDER:
            val_str = values[field_name]
            val_bytes = val_str.encode("utf-8")
            line = f"{field_name}:{len(val_bytes)}:".encode("utf-8") + val_bytes + b"\n"
            canonical_lines.append(line)

        return b"".join(canonical_lines)

    @classmethod
    def canonicalize_from_model(cls, record: Any) -> bytes:
        """Constructs canonical bytes from a ProvenanceRecord database model instance."""
        return cls.canonicalize_provenance_record(
            event_id=record.event_id,
            document_id=record.document_id,
            document_version_id=record.document_version_id,
            user_id=record.user_id,
            recipient_key_id=record.recipient_key_id,
            recipient_key_version=record.recipient_key_version,
            device_id=record.device_id,
            decryption_session_id=record.decryption_session_id,
            policy_id=record.policy_id,
            policy_version=record.policy_version,
            access_type=record.access_type,
            approval_request_id=record.approval_request_id,
            emergency_access_request_id=record.emergency_access_request_id,
            document_plaintext_sha256=record.document_plaintext_sha256,
            document_ciphertext_sha256=record.document_ciphertext_sha256,
            event_timestamp=record.event_timestamp,
            protocol_version=record.protocol_version,
        )
