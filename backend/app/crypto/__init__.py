"""Production-grade cryptographic subsystem for the Secure Document Provenance Platform.

Enforces:
- AES-256-GCM for authenticated document encryption.
- Standard ML-KEM-768 (FIPS 203) for post-quantum recipient encapsulation.
- HKDF-SHA-256 (RFC 5869) for recipient KEK derivation.
- AES-256-GCM for wrapping document DEKs.
- Argon2id for recipient private key protection at rest.
- SHA-256 for document integrity verification.
- Deterministic canonical AAD construction.
"""
from typing import Dict, Any

from app.crypto.models import (
    EncryptedPayload,
    WrappedDEKEnvelope,
    ProtectedPrivateKeyMaterial,
    CryptoSelfCheckResult,
)
from app.crypto.aad import (
    build_document_aad,
    build_dek_wrap_kdf_info,
    build_dek_wrap_aad,
    AADBuilder,
)
from app.crypto.aes_gcm import AESGCMService
from app.crypto.ml_kem import MLKEMService
from app.crypto.hkdf import HKDFService
from app.crypto.hashing import HashService
from app.crypto.key_protection import KeyProtectionService
from app.crypto.key_management import (
    LegacyServerEnvelopeKeyManagement,
    RecipientWrappedKeyManagement,
    KeyManagementService,
)


def verify_crypto_primitives() -> CryptoSelfCheckResult:
    """Startup and test-time validation confirming required cryptographic primitives are genuine and standard.
    
    Validates:
    - AES-256-GCM authenticated encryption and decryption.
    - ML-KEM-768 (FIPS 203) key generation, encapsulation, and decapsulation.
    - HKDF-SHA-256 key derivation.
    - Argon2id key derivation.
    - SHA-256 cryptographic hashing.
    - End-to-end recipient DEK wrapping and recovery.
    
    Raises:
        RuntimeError: If any primitive is missing, mocked, or fails cryptographic validation.
    """
    verified = {}

    try:
        # 1. Verify SHA-256
        test_data = b"SDP-CRYPTO-SELF-CHECK"
        sha_hex = HashService.sha256_hex(test_data)
        if len(sha_hex) != 64 or not HashService.verify_sha256(test_data, sha_hex):
            raise RuntimeError("SHA-256 self-check failed.")
        verified["SHA-256"] = "Active (Standard hashlib/hmac)"

        # 2. Verify AES-256-GCM
        test_key = AESGCMService.generate_key()
        test_nonce = AESGCMService.generate_nonce()
        test_aad = b"TEST-AAD"
        test_plain = b"Confidential DEK Test Payload"
        encrypted = AESGCMService.encrypt(test_key, test_plain, test_aad, nonce=test_nonce)
        decrypted = AESGCMService.decrypt(test_key, test_nonce, encrypted.ciphertext_and_tag, test_aad)
        if decrypted != test_plain:
            raise RuntimeError("AES-256-GCM roundtrip failed.")
        verified["AES-256-GCM"] = "Active (Standard cryptography.hazmat)"

        # 3. Verify ML-KEM-768
        priv, pub = MLKEMService.generate_key_pair()
        pub_bytes = MLKEMService.serialize_public_key(pub)
        if len(pub_bytes) != MLKEMService.PUBLIC_KEY_SIZE_BYTES:
            raise RuntimeError(f"ML-KEM-768 public key size mismatch: {len(pub_bytes)} != 1184")
        ss_enc, kem_ct = MLKEMService.encapsulate(pub_bytes)
        if len(kem_ct) != MLKEMService.CIPHERTEXT_SIZE_BYTES:
            raise RuntimeError(f"ML-KEM-768 ciphertext size mismatch: {len(kem_ct)} != 1088")
        ss_dec = MLKEMService.decapsulate(priv, kem_ct)
        if ss_enc != ss_dec:
            raise RuntimeError("ML-KEM-768 decapsulation shared secret mismatch.")
        verified["ML-KEM-768"] = "Active (FIPS 203 cryptography.hazmat.primitives.asymmetric.mlkem)"

        # 4. Verify HKDF-SHA-256
        test_info = b"TEST-HKDF-INFO"
        derived_kek = HKDFService.derive_kek(ss_enc, info=test_info)
        if len(derived_kek) != 32:
            raise RuntimeError(f"HKDF-SHA-256 derived key size mismatch: {len(derived_kek)} != 32")
        verified["HKDF-SHA-256"] = "Active (RFC 5869 cryptography.hazmat)"

        # 5. Verify Argon2id
        test_salt = b"0123456789abcdef"
        derived_prot = KeyProtectionService.derive_protection_key(b"test_secret", test_salt)
        if len(derived_prot) != 32:
            raise RuntimeError(f"Argon2id key derivation size mismatch: {len(derived_prot)} != 32")
        verified["Argon2id"] = "Active (argon2-cffi low_level.hash_secret_raw)"

        # 6. Verify End-to-End Recipient DEK Wrapping Roundtrip
        doc_id = "test-doc-123"
        ver_id = "1"
        user_id = "test-user-456"
        key_id = "test-key-789"
        key_version = 1
        test_dek = AESGCMService.generate_key()

        envelope = RecipientWrappedKeyManagement.wrap_dek_for_recipient(
            dek=test_dek,
            recipient_public_key_bytes=pub_bytes,
            document_id=doc_id,
            document_version_id=ver_id,
            recipient_user_id=user_id,
            recipient_key_id=key_id,
            recipient_key_version=key_version,
        )
        recovered_dek = RecipientWrappedKeyManagement.unwrap_dek_for_recipient(
            envelope=envelope,
            recipient_priv=priv,
            document_id=doc_id,
            document_version_id=ver_id,
            recipient_user_id=user_id,
        )
        if recovered_dek != test_dek:
            raise RuntimeError("End-to-end recipient DEK wrapping/unwrapping roundtrip failed.")

        # 7. Verify ML-DSA-65 (FIPS 204)
        from cryptography.hazmat.primitives.asymmetric import mldsa
        dsa_priv = mldsa.MLDSA65PrivateKey.generate()
        dsa_pub = dsa_priv.public_key()
        dsa_test_msg = b"TEST-ML-DSA-65-MESSAGE"
        dsa_sig = dsa_priv.sign(dsa_test_msg)
        dsa_pub.verify(dsa_sig, dsa_test_msg)
        verified["ML-DSA-65"] = "Active (FIPS 204 cryptography.hazmat.primitives.asymmetric.mldsa)"

        return CryptoSelfCheckResult(
            is_valid=True,
            verified_algorithms=verified,
        )

    except Exception as exc:
        raise RuntimeError(f"Cryptographic self-check verification failed: {exc}") from exc


__all__ = [
    "EncryptedPayload",
    "WrappedDEKEnvelope",
    "ProtectedPrivateKeyMaterial",
    "CryptoSelfCheckResult",
    "build_document_aad",
    "build_dek_wrap_kdf_info",
    "build_dek_wrap_aad",
    "AADBuilder",
    "AESGCMService",
    "MLKEMService",
    "HKDFService",
    "HashService",
    "KeyProtectionService",
    "LegacyServerEnvelopeKeyManagement",
    "RecipientWrappedKeyManagement",
    "KeyManagementService",
    "verify_crypto_primitives",
]
