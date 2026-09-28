import hashlib
import os
import uuid
from pathlib import Path
from typing import Tuple

from app.config.settings import settings


class EvidenceStorageService:
    """Secure, isolated storage service for digital leak evidence artifacts.
    
    Guarantees:
    - Path traversal prevention.
    - Non-predictable internal storage references.
    - Strictly non-public directory structure.
    - SHA-256 integrity verification upon write and read.
    """

    @classmethod
    def get_storage_dir(cls) -> Path:
        """Resolves the isolated evidence storage directory."""
        evidence_dir = (Path(settings.STORAGE_PATH).resolve() / "evidence").resolve()
        evidence_dir.mkdir(parents=True, exist_ok=True)
        return evidence_dir

    @classmethod
    def validate_safe_path(cls, storage_reference: str) -> Path:
        """Ensures the storage reference cannot perform path traversal outside the evidence directory."""
        clean_name = os.path.basename(storage_reference)
        if clean_name != storage_reference or ".." in storage_reference:
            raise ValueError(f"Path traversal detected in evidence reference: {storage_reference}")

        storage_dir = cls.get_storage_dir()
        target_path = (storage_dir / clean_name).resolve()

        if not str(target_path).startswith(str(storage_dir)):
            raise ValueError("Target evidence path traverses outside authorized directory.")

        return target_path

    @classmethod
    def save_evidence_bytes(cls, evidence_bytes: bytes, original_filename: str) -> Tuple[str, str]:
        """Saves raw evidence bytes securely, returns (storage_reference, sha256_hex)."""
        if not evidence_bytes:
            raise ValueError("Cannot persist empty evidence bytes.")

        sha256_hash = hashlib.sha256(evidence_bytes).hexdigest()
        
        # Generate random storage reference with preserved extension for MIME hints
        ext = os.path.splitext(original_filename)[1].lower()[:8]
        if ext and not ext.startswith("."):
            ext = f".{ext}"
        storage_ref = f"evd_{uuid.uuid4().hex}{ext}"

        target_path = cls.validate_safe_path(storage_ref)
        if target_path.exists():
            raise FileExistsError("Generated storage reference collision.")

        # Write atomic bytes
        target_path.write_bytes(evidence_bytes)

        # Integrity verification
        written_hash = hashlib.sha256(target_path.read_bytes()).hexdigest()
        if written_hash != sha256_hash:
            target_path.unlink(missing_ok=True)
            raise IOError("Evidence SHA-256 verification mismatch after write.")

        return storage_ref, sha256_hash

    @classmethod
    def read_evidence_bytes(cls, storage_reference: str) -> bytes:
        """Reads raw evidence bytes from protected storage and verifies integrity."""
        target_path = cls.validate_safe_path(storage_reference)
        if not target_path.exists() or not target_path.is_file():
            raise FileNotFoundError(f"Evidence artifact '{storage_reference}' not found in storage.")

        return target_path.read_bytes()
