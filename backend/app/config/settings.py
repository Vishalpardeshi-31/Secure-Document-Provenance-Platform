import base64
from typing import List, Union, Optional
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Deterministic non-random development key (exactly 32 bytes when base64-decoded)
DEV_DEFAULT_KEK_BASE64 = "dGVzdC1kZXZlbG9wbWVudC1tYXN0ZXIta2VrLTMyYnk="
DEV_DEFAULT_RECIPIENT_KEK_BASE64 = "cmVjaXBpZW50LXByb3RlY3Rpb24ta2VrLTMyYnl0ZXM="
DEV_DEFAULT_PROVENANCE_KEK_BASE64 = "cHJvdmVuYW5jZS1rZXktcHJvdGVjdGlvbi1rZWstMzI="


class Settings(BaseSettings):
    PROJECT_NAME: str = "Secure Document Provenance Platform"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"

    # Database
    DATABASE_URL: str = Field(
        default="postgresql+psycopg://postgres:postgres@localhost:5432/secure_docs",
        description="SQLAlchemy database connection URL",
    )

    # Security & Tokens
    SECRET_KEY: str = Field(
        default="change-me-in-production-minimum-32-chars-long-secret-key",
        description="Cryptographic secret key for signing tokens",
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Cryptographic Key Encryption Key (KEK) for protecting document DEKs
    DOCUMENT_KEK_BASE64: Optional[str] = Field(
        default=DEV_DEFAULT_KEK_BASE64,
        description="Base64-encoded 256-bit Key Encryption Key (KEK) for document DEKs",
    )

    # Dedicated Key-Protection Key (KEK) for protecting recipient private keys at rest
    RECIPIENT_KEY_KEK_BASE64: Optional[str] = Field(
        default=DEV_DEFAULT_RECIPIENT_KEK_BASE64,
        description="Base64-encoded 256-bit Key Encryption Key for recipient private keys",
    )

    # Dedicated Key-Protection Key (KEK) for protecting ML-DSA provenance signing keys at rest
    PROVENANCE_KEY_KEK_BASE64: Optional[str] = Field(
        default=DEV_DEFAULT_PROVENANCE_KEK_BASE64,
        description="Base64-encoded 256-bit Key Encryption Key for provenance signing keys",
    )

    # Document Upload Limits
    MAX_DOCUMENT_SIZE_MB: int = Field(
        default=25,
        description="Maximum allowed document size in megabytes",
    )

    # CORS
    CORS_ORIGINS: Union[str, List[str]] = Field(
        default="http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173",
        description="Comma-separated or list of allowed CORS origins",
    )

    # Storage Path (for encrypted storage references)
    STORAGE_PATH: str = Field(
        default="./storage/encrypted",
        description="Path reserved for encrypted document storage",
    )

    @field_validator("CORS_ORIGINS", mode="after")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @model_validator(mode="after")
    def validate_cryptographic_configuration(self) -> "Settings":
        """Strict startup validation for cryptographic master keys."""
        kek_b64 = self.DOCUMENT_KEK_BASE64
        rkek_b64 = self.RECIPIENT_KEY_KEK_BASE64

        if self.ENVIRONMENT == "production":
            if not kek_b64 or kek_b64 == DEV_DEFAULT_KEK_BASE64:
                raise ValueError(
                    "CRITICAL: Production deployment requires a secure, non-default DOCUMENT_KEK_BASE64 environment variable."
                )
            if not rkek_b64 or rkek_b64 == DEV_DEFAULT_RECIPIENT_KEK_BASE64:
                raise ValueError(
                    "CRITICAL: Production deployment requires a secure, non-default RECIPIENT_KEY_KEK_BASE64 environment variable."
                )

        for name, val in [
            ("DOCUMENT_KEK_BASE64", kek_b64),
            ("RECIPIENT_KEY_KEK_BASE64", rkek_b64),
            ("PROVENANCE_KEY_KEK_BASE64", self.PROVENANCE_KEY_KEK_BASE64),
        ]:
            if val:
                try:
                    decoded = base64.b64decode(val)
                    if len(decoded) != 32:
                        raise ValueError(
                            f"{name} must decode to exactly 32 bytes (256 bits). Found {len(decoded)} bytes."
                        )
                except Exception as e:
                    if isinstance(e, ValueError) and "32 bytes" in str(e):
                        raise
                    raise ValueError(f"{name} is not valid base64: {e}")

        return self

    def get_kek_bytes(self) -> bytes:
        """Returns the decoded 32-byte master key encryption key for document DEKs."""
        if not self.DOCUMENT_KEK_BASE64:
            raise ValueError("DOCUMENT_KEK_BASE64 is not configured.")
        return base64.b64decode(self.DOCUMENT_KEK_BASE64)

    def get_recipient_kek_bytes(self) -> bytes:
        """Returns the decoded 32-byte key-protection key for recipient private keys."""
        if not self.RECIPIENT_KEY_KEK_BASE64:
            raise ValueError("RECIPIENT_KEY_KEK_BASE64 is not configured.")
        return base64.b64decode(self.RECIPIENT_KEY_KEK_BASE64)

    def get_provenance_kek_bytes(self) -> bytes:
        """Returns the decoded 32-byte key-protection key for provenance signing keys."""
        if not self.PROVENANCE_KEY_KEK_BASE64:
            raise ValueError("PROVENANCE_KEY_KEK_BASE64 is not configured.")
        return base64.b64decode(self.PROVENANCE_KEY_KEK_BASE64)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
