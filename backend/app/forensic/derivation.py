import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import List, Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config.settings import settings


# 16-bit synchronization preamble (0xB729: 1011 0111 0010 1001)
SYNC_PREAMBLE_16 = [1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1]


def compute_crc16(data_bytes: bytes) -> int:
    """Computes standard CRC16-CCITT checksum over the provided bytes."""
    crc = 0xFFFF
    for b in data_bytes:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


@dataclass(frozen=True)
class DerivedFingerprintMaterial:
    """Cryptographic fingerprint derivation container."""
    fingerprint_token: str
    fingerprint_commitment: str
    fingerprint_nonce: str
    derived_material: bytes
    payload_bits: List[int]  # 64 bits: 16 sync + 32 token + 16 CRC


class FingerprintDerivationService:
    """Standardized cryptographic key derivation for session-specific forensic fingerprints."""

    PROTOCOL_VERSION = "SDP-FORENSIC-V1"
    FINGERPRINT_VERSION = 1
    ALGORITHM = "HKDF-SHA256-DSSS-DCT"

    @classmethod
    def generate_nonce(cls) -> str:
        """Generates a cryptographically secure 16-byte random nonce (32 hex characters)."""
        return secrets.token_hex(16)

    @classmethod
    def derive_fingerprint(
        cls,
        document_id: str,
        document_version_id: str,
        recipient_user_id: str,
        decryption_session_id: str,
        viewer_session_id: str,
        provenance_event_id: str,
        nonce: Optional[str] = None,
        master_key: Optional[bytes] = None,
    ) -> DerivedFingerprintMaterial:
        """Derives a deterministic, cryptographically bound fingerprint for a viewing event."""
        if not nonce:
            nonce = cls.generate_nonce()

        ikm = master_key if master_key is not None else settings.get_forensic_master_key_bytes()
        salt = hashlib.sha256(f"{document_id}|{document_version_id}".encode("utf-8")).digest()
        
        info = (
            f"{cls.PROTOCOL_VERSION}|"
            f"{document_id}|"
            f"{document_version_id}|"
            f"{recipient_user_id}|"
            f"{decryption_session_id}|"
            f"{viewer_session_id}|"
            f"{provenance_event_id}|"
            f"{nonce}"
        ).encode("utf-8")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        )
        derived_material = hkdf.derive(ikm)

        token_bytes = derived_material[:4]
        token_hex = token_bytes.hex().upper()
        commitment = hashlib.sha256(derived_material).hexdigest()

        # Build 64-bit payload: 16-bit sync preamble + 32-bit token + 16-bit CRC16
        payload_bits = cls.build_payload_bits(token_bytes)

        return DerivedFingerprintMaterial(
            fingerprint_token=token_hex,
            fingerprint_commitment=commitment,
            fingerprint_nonce=nonce,
            derived_material=derived_material,
            payload_bits=payload_bits,
        )

    @classmethod
    def build_payload_bits(cls, token_bytes: bytes) -> List[int]:
        """Encodes token bytes with sync preamble and CRC16 into exactly 64 bits."""
        assert len(token_bytes) == 4, "Token must be exactly 4 bytes (32 bits)"

        token_bits: List[int] = []
        for b in token_bytes:
            for i in range(7, -1, -1):
                token_bits.append((b >> i) & 1)

        crc = compute_crc16(token_bytes)
        crc_bits: List[int] = []
        for i in range(15, -1, -1):
            crc_bits.append((crc >> i) & 1)

        payload = list(SYNC_PREAMBLE_16) + token_bits + crc_bits
        assert len(payload) == 64, f"Payload must be 64 bits, got {len(payload)}"
        return payload

    @classmethod
    def parse_payload_bits(cls, bits: List[int]) -> Tuple[Optional[str], float]:
        """Validates synchronization preamble and CRC16 on recovered 64 bits.
        
        Returns:
            Tuple of (token_hex or None, preamble_match_rate).
        """
        if len(bits) < 64:
            return None, 0.0

        preamble_candidate = bits[:16]
        matches = sum(1 for a, b in zip(preamble_candidate, SYNC_PREAMBLE_16) if a == b)
        match_rate = matches / 16.0

        # Allow at most 1 bit error in preamble for extreme transformation tolerance
        if matches < 15:
            return None, match_rate

        token_bits = bits[16:48]
        crc_bits = bits[48:64]

        # Reconstruct token bytes
        token_byte_vals = []
        for byte_idx in range(4):
            val = 0
            for bit_offset in range(8):
                val = (val << 1) | token_bits[byte_idx * 8 + bit_offset]
            token_byte_vals.append(val)
        token_bytes = bytes(token_byte_vals)

        # Reconstruct expected CRC16
        expected_crc = compute_crc16(token_bytes)

        recovered_crc = 0
        for bit in crc_bits:
            recovered_crc = (recovered_crc << 1) | bit

        if expected_crc == recovered_crc:
            return token_bytes.hex().upper(), match_rate

        return None, match_rate
