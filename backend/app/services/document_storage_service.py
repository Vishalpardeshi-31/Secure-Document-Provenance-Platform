import os
import uuid
from pathlib import Path
from typing import Optional
from app.config.settings import settings


class DocumentStorageService:
    """Secure backend storage abstraction for encrypted document ciphertexts.
    
    Guarantees:
    - Files are stored outside public/static web assets.
    - Storage references are server-generated opaque UUIDs.
    - Path traversal attacks are strictly validated and blocked.
    """

    @staticmethod
    def get_storage_dir() -> Path:
        """Resolves the absolute storage directory path and ensures it exists."""
        storage_dir = Path(settings.STORAGE_PATH).resolve()
        storage_dir.mkdir(parents=True, exist_ok=True)
        return storage_dir

    @staticmethod
    def generate_storage_reference() -> str:
        """Generates a non-predictable, server-controlled storage filename."""
        return f"enc_{uuid.uuid4().hex}.enc"

    @staticmethod
    def validate_safe_path(storage_reference: str) -> Path:
        """Ensures the storage reference cannot perform path traversal outside the storage directory."""
        clean_name = os.path.basename(storage_reference)
        if clean_name != storage_reference or ".." in storage_reference:
            raise ValueError(f"Path traversal detected in storage reference: {storage_reference}")

        storage_dir = DocumentStorageService.get_storage_dir()
        target_path = (storage_dir / clean_name).resolve()

        # Check path boundary
        if not str(target_path).startswith(str(storage_dir)):
            raise ValueError("Target storage path traverses outside authorized storage directory.")

        return target_path

    @staticmethod
    def save_encrypted_bytes(ciphertext: bytes, storage_reference: Optional[str] = None) -> str:
        """Persists encrypted bytes to the storage location and returns the storage reference."""
        ref = storage_reference or DocumentStorageService.generate_storage_reference()
        target_path = DocumentStorageService.validate_safe_path(ref)

        with open(target_path, "wb") as f:
            f.write(ciphertext)

        return ref

    @staticmethod
    def read_encrypted_bytes(storage_reference: str) -> bytes:
        """Internal retrieval of encrypted bytes from secure storage."""
        target_path = DocumentStorageService.validate_safe_path(storage_reference)
        if not target_path.exists():
            raise FileNotFoundError(f"Encrypted artifact '{storage_reference}' not found in storage.")

        with open(target_path, "rb") as f:
            return f.read()

    @staticmethod
    def delete_encrypted_bytes(storage_reference: str) -> bool:
        """Deletes encrypted file from storage."""
        try:
            target_path = DocumentStorageService.validate_safe_path(storage_reference)
            if target_path.exists():
                os.remove(target_path)
                return True
            return False
        except Exception:
            return False
