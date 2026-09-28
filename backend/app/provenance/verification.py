"""Cryptographic verification service for provenance records."""
import base64
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from app.provenance.models import ProvenanceRecord, ProvenanceSigningKey
from app.provenance.canonicalization import CanonicalizationService
from app.provenance.hashing import ProvenanceHashService
from app.provenance.exceptions import ProvenanceVerificationError, ProvenanceKeyError


class ProvenanceVerificationService:
    """Verifies the integrity, authenticity, and post-quantum digital signature of provenance records."""

    @classmethod
    def load_public_key(cls, pub_pem: str) -> mldsa.MLDSA65PublicKey:
        """Deserializes an ML-DSA-65 public key from PEM encoding."""
        try:
            pub = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
            if not isinstance(pub, mldsa.MLDSA65PublicKey):
                raise ProvenanceVerificationError(f"Loaded public key is not an MLDSA65PublicKey: {type(pub)}")
            return pub
        except Exception as e:
            raise ProvenanceVerificationError(f"Failed to load ML-DSA-65 public key: {e}")

    @classmethod
    def verify_record(
        cls,
        db: Session,
        record: ProvenanceRecord,
        override_public_key_pem: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cryptographically verifies a provenance record.
        
        Steps:
        1. Look up the historical public key corresponding to record.signature_key_version.
        2. Reconstruct the deterministic canonical bytes from record fields.
        3. Recalculate SHA-256 over canonical bytes and verify against record.canonical_record_hash.
        4. Cryptographically verify the ML-DSA-65 signature against the canonical bytes.
        5. Return verification results.
        
        Returns:
            dict with:
                - event_id
                - hash_valid (bool)
                - signature_valid (bool)
                - signing_key_version (int)
                - verified (bool)
                - reason (str if failed)
        """
        # Step 1: Reconstruct canonical bytes
        canonical_bytes = CanonicalizationService.canonicalize_from_model(record)

        # Step 2: Recalculate SHA-256 hash
        recalculated_hash = ProvenanceHashService.hash_canonical_record(canonical_bytes)
        stored_hash = str(record.canonical_record_hash).strip().lower()
        hash_valid = (recalculated_hash == stored_hash)

        # Step 3: Fetch public key
        if override_public_key_pem:
            pub_pem = override_public_key_pem
        else:
            key_model = (
                db.query(ProvenanceSigningKey)
                .filter(ProvenanceSigningKey.key_version == record.signature_key_version)
                .first()
            )
            if not key_model:
                return {
                    "event_id": record.event_id,
                    "hash_valid": hash_valid,
                    "signature_valid": False,
                    "signing_key_version": record.signature_key_version,
                    "verified": False,
                    "reason": f"Signing key version {record.signature_key_version} not found in database.",
                }
            pub_pem = key_model.public_key

        # Step 4: Verify ML-DSA signature
        signature_valid = False
        reason = None

        try:
            pub = cls.load_public_key(pub_pem)
            raw_signature = base64.b64decode(record.signature)
            pub.verify(raw_signature, canonical_bytes)
            signature_valid = True
        except InvalidSignature:
            signature_valid = False
            reason = "ML-DSA-65 signature verification failed: signature does not match canonical provenance record."
        except Exception as e:
            signature_valid = False
            reason = f"Verification error: {e}"

        overall_verified = hash_valid and signature_valid
        if not hash_valid and not reason:
            reason = "Canonical record hash mismatch: record fields have been modified after signing."

        return {
            "event_id": record.event_id,
            "hash_valid": hash_valid,
            "signature_valid": signature_valid,
            "signing_key_version": record.signature_key_version,
            "verified": overall_verified,
            "reason": reason,
        }
