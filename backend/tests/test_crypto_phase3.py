import pytest
import os
import base64
from app.security.crypto_service import CryptoService
from app.security.key_management_service import KeyManagementService
from app.config.settings import Settings


def test_encrypt_known_bytes_and_differ_from_plaintext():
    """Verify AES-256-GCM encryption of known bytes produces differing ciphertext."""
    key = CryptoService.generate_dek()
    nonce = CryptoService.generate_nonce()
    plaintext = b"TOP SECRET MISSION DIRECTIVE 2026"

    ciphertext = CryptoService.encrypt_bytes(key, nonce, plaintext)

    assert ciphertext != plaintext
    assert len(ciphertext) == len(plaintext) + CryptoService.TAG_SIZE_BYTES
    assert plaintext not in ciphertext


def test_aes_gcm_authentication_and_internal_decryption():
    """Verify AES-GCM internal round-trip authentication and decryption."""
    key = CryptoService.generate_dek()
    nonce = CryptoService.generate_nonce()
    plaintext = b"Sensitive Payload Data - High Assurance"

    ciphertext = CryptoService.encrypt_bytes(key, nonce, plaintext, associated_data=b"AAD-TEST")
    decrypted = CryptoService.decrypt_bytes(key, nonce, ciphertext, associated_data=b"AAD-TEST")

    assert decrypted == plaintext


def test_tampering_with_ciphertext_causes_authentication_failure():
    """Verify that bit tampering anywhere in ciphertext or tag causes decryption failure."""
    key = CryptoService.generate_dek()
    nonce = CryptoService.generate_nonce()
    plaintext = b"Cryptographic Integrity Verification String"

    ciphertext = bytearray(CryptoService.encrypt_bytes(key, nonce, plaintext))

    # Tamper with single byte
    ciphertext[5] ^= 0xFF

    with pytest.raises(ValueError, match="tampered with"):
        CryptoService.decrypt_bytes(key, nonce, bytes(ciphertext))


def test_different_encryptions_produce_different_ciphertexts_and_nonces():
    """Verify that encrypting identical plaintext twice produces distinct nonces and ciphertexts."""
    plaintext = b"Repeatable Identical Source Content"
    key = CryptoService.generate_dek()

    nonce1 = CryptoService.generate_nonce()
    ciphertext1 = CryptoService.encrypt_bytes(key, nonce1, plaintext)

    nonce2 = CryptoService.generate_nonce()
    ciphertext2 = CryptoService.encrypt_bytes(key, nonce2, plaintext)

    assert nonce1 != nonce2
    assert ciphertext1 != ciphertext2


def test_dek_envelope_protect_and_unprotect():
    """Verify DEK can be securely wrapped with KEK and unwrapped internally."""
    kek = os.urandom(32)
    dek = CryptoService.generate_dek()

    wrapped_b64 = KeyManagementService.wrap_dek(dek, custom_kek=kek)
    assert isinstance(wrapped_b64, str)
    assert dek not in base64.b64decode(wrapped_b64)

    unwrapped_dek = KeyManagementService.unwrap_dek(wrapped_b64, custom_kek=kek)
    assert unwrapped_dek == dek


def test_invalid_kek_configuration_fails_safely():
    """Verify that an invalid KEK (not 32 bytes) raises a clear ValueError."""
    invalid_short_kek = b"too-short-key"
    dek = CryptoService.generate_dek()

    with pytest.raises(ValueError, match="32 bytes"):
        KeyManagementService.wrap_dek(dek, custom_kek=invalid_short_kek)


def test_production_mode_refuses_default_or_missing_kek():
    """Verify startup validation rejects default KEK in production mode."""
    with pytest.raises(ValueError, match="Production deployment requires a secure, non-default DOCUMENT_KEK_BASE64"):
        Settings(
            ENVIRONMENT="production",
            DOCUMENT_KEK_BASE64="dGVzdC1kZXZlbG9wbWVudC1tYXN0ZXIta2VrLTMyYnk=",
        )
