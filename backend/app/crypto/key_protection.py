"""Recipient private key protection at rest using Argon2id KDF and AES-256-GCM authenticated encryption."""
import os
import json
import base64
from typing import Dict, Any, Optional
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.asymmetric import mlkem
from app.crypto.aes_gcm import AESGCMService
from app.crypto.models import ProtectedPrivateKeyMaterial


class KeyProtectionService:
    """Protects recipient private key material at rest using Argon2id-derived keys.
    
    Flow:
    1. Generates a fresh 16-byte CSPRNG salt.
    2. Derives a 256-bit symmetric protection key from the recipient's authentication secret using Argon2id.
    3. Generates a fresh 12-byte CSPRNG nonce.
    4. Binds recipient identity and key version into deterministic AAD.
    5. Encrypts the raw private key seed (64 bytes) with AES-256-GCM.
    6. Returns metadata structure with encrypted payload, salt, nonce, and KDF parameters.
    
    Security Guarantee:
    - No plaintext private keys are ever stored in the database.
    - No Argon2id derived protection keys are ever stored.
    - No ML-KEM shared secrets or recipient KEKs are ever stored.
    """

    KDF_ALGORITHM = "Argon2id"
    ENCRYPTION_ALGORITHM = "AES-256-GCM"
    SALT_SIZE_BYTES = 16
    DEFAULT_TIME_COST = 2
    DEFAULT_MEMORY_COST = 65536  # 64 MiB
    DEFAULT_PARALLELISM = 1
    KEY_LEN_BYTES = 32

    @classmethod
    def derive_protection_key(
        cls,
        auth_secret: bytes,
        salt: bytes,
        time_cost: int = DEFAULT_TIME_COST,
        memory_cost: int = DEFAULT_MEMORY_COST,
        parallelism: int = DEFAULT_PARALLELISM,
    ) -> bytes:
        """Derives a 256-bit protection key using Argon2id."""
        if not auth_secret:
            raise ValueError("Authentication secret must not be empty.")
        if len(salt) < 16:
            raise ValueError("Argon2id salt must be at least 16 bytes.")

        return hash_secret_raw(
            secret=auth_secret,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=cls.KEY_LEN_BYTES,
            type=Type.ID,
        )

    @classmethod
    def protect_private_key(
        cls,
        priv: mlkem.MLKEM768PrivateKey,
        auth_secret: str,
        user_id: str,
        key_version: int,
    ) -> ProtectedPrivateKeyMaterial:
        """Protects an ML-KEM-768 private key using Argon2id and AES-256-GCM.
        
        Args:
            priv: The ML-KEM-768 private key to protect.
            auth_secret: The recipient's authentication secret/password.
            user_id: Recipient user ID for AAD binding.
            key_version: Recipient key version for AAD binding.
            
        Returns:
            ProtectedPrivateKeyMaterial containing encrypted ciphertext, salt, nonce, and KDF metadata.
        """
        # Step 1: Generate unique random salt
        salt = os.urandom(cls.SALT_SIZE_BYTES)

        # Step 2: Derive 256-bit protection key via Argon2id
        kdf_params = {
            "time_cost": cls.DEFAULT_TIME_COST,
            "memory_cost": cls.DEFAULT_MEMORY_COST,
            "parallelism": cls.DEFAULT_PARALLELISM,
            "hash_len": cls.KEY_LEN_BYTES,
        }
        protection_key = cls.derive_protection_key(
            auth_secret=auth_secret.encode("utf-8"),
            salt=salt,
            time_cost=cls.DEFAULT_TIME_COST,
            memory_cost=cls.DEFAULT_MEMORY_COST,
            parallelism=cls.DEFAULT_PARALLELISM,
        )

        # Step 3: Raw private seed (FIPS 203 d and z seeds, 64 bytes)
        raw_seed = priv.private_bytes_raw()

        # Step 4: Deterministic AAD binding
        aad = f"SDP-PRIVKEY-PROTECT-V1|{user_id}|v{key_version}".encode("utf-8")

        # Step 5: Fresh 12-byte nonce and AES-256-GCM encryption
        nonce = AESGCMService.generate_nonce()
        encrypted = AESGCMService.encrypt(
            key=protection_key,
            plaintext=raw_seed,
            associated_data=aad,
            nonce=nonce,
        )

        return ProtectedPrivateKeyMaterial(
            encrypted_private_key=base64.b64encode(encrypted.ciphertext_and_tag).decode("ascii"),
            kdf_algorithm=cls.KDF_ALGORITHM,
            kdf_salt=salt.hex(),
            kdf_parameters=kdf_params,
            encryption_algorithm=cls.ENCRYPTION_ALGORITHM,
            encryption_nonce=nonce.hex(),
            key_version=key_version,
        )

    @classmethod
    def recover_private_key(
        cls,
        protected: ProtectedPrivateKeyMaterial,
        auth_secret: str,
        user_id: str,
    ) -> mlkem.MLKEM768PrivateKey:
        """Recovers the ML-KEM-768 private key from protected material.
        
        Args:
            protected: ProtectedPrivateKeyMaterial instance.
            auth_secret: Recipient's authentication secret/password.
            user_id: Recipient user ID for AAD verification.
            
        Returns:
            Recovered MLKEM768PrivateKey instance.
            
        Raises:
            ValueError: If authentication secret is invalid or key material has been modified.
        """
        if not protected.kdf_salt or not protected.encryption_nonce:
            raise ValueError("Protected key material missing salt or nonce.")

        salt = bytes.fromhex(protected.kdf_salt)
        nonce = bytes.fromhex(protected.encryption_nonce)
        ciphertext_and_tag = base64.b64decode(protected.encrypted_private_key)

        params = protected.kdf_parameters or {}
        time_cost = params.get("time_cost", cls.DEFAULT_TIME_COST)
        memory_cost = params.get("memory_cost", cls.DEFAULT_MEMORY_COST)
        parallelism = params.get("parallelism", cls.DEFAULT_PARALLELISM)

        # Derive same protection key
        protection_key = cls.derive_protection_key(
            auth_secret=auth_secret.encode("utf-8"),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
        )

        aad = f"SDP-PRIVKEY-PROTECT-V1|{user_id}|v{protected.key_version}".encode("utf-8")

        try:
            raw_seed = AESGCMService.decrypt(
                key=protection_key,
                nonce=nonce,
                ciphertext_and_tag=ciphertext_and_tag,
                associated_data=aad,
            )
        except Exception:
            raise ValueError("Failed to decrypt recipient private key: invalid authentication secret or corrupted data.")

        return mlkem.MLKEM768PrivateKey.from_seed_bytes(raw_seed)
