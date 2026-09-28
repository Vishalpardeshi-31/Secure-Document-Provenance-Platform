import base64
import os
import pytest
from cryptography.hazmat.primitives.asymmetric import mlkem
from app.config.settings import Settings, DEV_DEFAULT_RECIPIENT_KEK_BASE64
from app.security.crypto_service import CryptoService
from app.security.key_management_service import KeyManagementService
from app.security.recipient_key_manager import RecipientKeyManager
from app.models.user import User
from app.models.role import UserRole
from app.models.recipient_key import RecipientKey


def test_mlkem_key_generation_and_serialization():
    """Verifies that real post-quantum ML-KEM-768 key pairs generate, serialize, and reconstruct."""
    priv, pub = RecipientKeyManager.generate_key_pair()

    pub_bytes = pub.public_bytes_raw()
    assert len(pub_bytes) == 1184  # NIST FIPS 203 ML-KEM-768 public key length

    priv_seed = priv.private_bytes_raw()
    assert len(priv_seed) == 64  # NIST FIPS 203 seed length

    # Reconstruct from bytes
    rebuilt_pub = mlkem.MLKEM768PublicKey.from_public_bytes(pub_bytes)
    assert rebuilt_pub.public_bytes_raw() == pub_bytes

    rebuilt_priv = mlkem.MLKEM768PrivateKey.from_seed_bytes(priv_seed)
    assert rebuilt_priv.public_key().public_bytes_raw() == pub_bytes


def test_recipient_private_key_protection_at_rest(db_session):
    """Verifies that recipient private keys are encrypted at rest using RECIPIENT_KEY_KEK and never in plaintext."""
    admin = User(
        username="admin_crypto_test",
        email="admin_crypto@test.com",
        password_hash="argon2id$mockhash",
        role=UserRole.ADMIN.value,
    )
    recipient = User(
        username="rec_crypto_test",
        email="rec_crypto@test.com",
        password_hash="argon2id$mockhash",
        role=UserRole.RECIPIENT.value,
    )
    db_session.add_all([admin, recipient])
    db_session.commit()

    key_record = RecipientKeyManager.provision_recipient_key(db_session, recipient, admin)

    assert key_record.key_version == 1
    assert key_record.algorithm == "ML-KEM-768"
    assert key_record.status == "ACTIVE"
    assert key_record.public_key != ""
    assert key_record.encrypted_private_key != ""

    # Verify that raw seed is NOT in the encrypted_private_key string
    raw_priv = RecipientKeyManager._unwrap_private_key(key_record)
    raw_seed = raw_priv.private_bytes_raw()
    assert raw_seed.hex() not in key_record.encrypted_private_key
    assert base64.b64encode(raw_seed).decode() != key_record.encrypted_private_key


def test_mlkem_hkdf_aesgcm_wrapping_and_internal_unwrapping():
    """Cryptographic round-trip test: wrap a DEK for a recipient, unwrap internally, and verify match."""
    priv, pub = RecipientKeyManager.generate_key_pair()
    pub_b64 = base64.b64encode(pub.public_bytes_raw()).decode("ascii")

    # Generate a random 256-bit document DEK
    original_dek = CryptoService.generate_dek()
    assert len(original_dek) == 32

    # Wrap DEK for recipient
    enc_key_b64, nonce_b64, wrapped_dek_b64, algo = KeyManagementService.wrap_dek_for_recipient(
        dek=original_dek,
        recipient_public_key_b64=pub_b64,
    )

    assert algo == "ML-KEM-768+HKDF-SHA256+AES-256-GCM"
    assert enc_key_b64 != ""
    assert nonce_b64 != ""
    assert wrapped_dek_b64 != ""

    # Verify ciphertext differs completely from DEK
    assert original_dek not in base64.b64decode(wrapped_dek_b64)

    # Unwrap DEK internally using recipient's private key
    recovered_dek = KeyManagementService.unwrap_dek_for_recipient(
        encapsulated_key_b64=enc_key_b64,
        nonce_b64=nonce_b64,
        wrapped_dek_b64=wrapped_dek_b64,
        recipient_priv=priv,
    )

    assert recovered_dek == original_dek


def test_multi_recipient_distinct_wrapped_material():
    """Verifies that the same DEK wrapped for two different recipients produces distinct cryptographic material."""
    priv_a, pub_a = RecipientKeyManager.generate_key_pair()
    priv_b, pub_b = RecipientKeyManager.generate_key_pair()

    pub_a_b64 = base64.b64encode(pub_a.public_bytes_raw()).decode("ascii")
    pub_b_b64 = base64.b64encode(pub_b.public_bytes_raw()).decode("ascii")

    single_dek = CryptoService.generate_dek()

    enc_a, nonce_a, wrap_a, _ = KeyManagementService.wrap_dek_for_recipient(single_dek, pub_a_b64)
    enc_b, nonce_b, wrap_b, _ = KeyManagementService.wrap_dek_for_recipient(single_dek, pub_b_b64)

    # Distinct encapsulations
    assert enc_a != enc_b
    assert nonce_a != nonce_b
    assert wrap_a != wrap_b

    # Both unwrap to the exact same original DEK
    recovered_a = KeyManagementService.unwrap_dek_for_recipient(enc_a, nonce_a, wrap_a, priv_a)
    recovered_b = KeyManagementService.unwrap_dek_for_recipient(enc_b, nonce_b, wrap_b, priv_b)

    assert recovered_a == single_dek
    assert recovered_b == single_dek

    # Cross-decapsulation must fail (Recipient A's private key cannot unwrap Recipient B's material)
    with pytest.raises(Exception):
        KeyManagementService.unwrap_dek_for_recipient(enc_b, nonce_b, wrap_b, priv_a)


def test_tampering_with_wrapped_material_fails():
    """Verifies that tampering with either ML-KEM ciphertext or wrapped DEK raises authentication failure."""
    priv, pub = RecipientKeyManager.generate_key_pair()
    pub_b64 = base64.b64encode(pub.public_bytes_raw()).decode("ascii")
    dek = CryptoService.generate_dek()

    enc_key_b64, nonce_b64, wrapped_dek_b64, _ = KeyManagementService.wrap_dek_for_recipient(dek, pub_b64)

    # 1. Tamper with wrapped DEK bytes
    raw_wrapped = bytearray(base64.b64decode(wrapped_dek_b64))
    raw_wrapped[5] ^= 0xFF
    tampered_wrapped_b64 = base64.b64encode(bytes(raw_wrapped)).decode("ascii")

    with pytest.raises(Exception):
        KeyManagementService.unwrap_dek_for_recipient(enc_key_b64, nonce_b64, tampered_wrapped_b64, priv)

    # 2. Tamper with KEM ciphertext
    raw_enc = bytearray(base64.b64decode(enc_key_b64))
    raw_enc[10] ^= 0xFF
    tampered_enc_b64 = base64.b64encode(bytes(raw_enc)).decode("ascii")

    with pytest.raises(Exception):
        KeyManagementService.unwrap_dek_for_recipient(tampered_enc_b64, nonce_b64, wrapped_dek_b64, priv)


def test_key_versioning_and_revocation(db_session):
    """Verifies that provisioning generates incrementing key versions and revocation prevents active status."""
    admin = User(username="admin_v", email="admin_v@test.com", password_hash="h", role=UserRole.ADMIN.value)
    recipient = User(username="rec_v", email="rec_v@test.com", password_hash="h", role=UserRole.RECIPIENT.value)
    db_session.add_all([admin, recipient])
    db_session.commit()

    # Provision version 1
    key1 = RecipientKeyManager.provision_recipient_key(db_session, recipient, admin)
    assert key1.key_version == 1
    assert key1.status == "ACTIVE"

    # Provision version 2 (should supersede version 1)
    key2 = RecipientKeyManager.provision_recipient_key(db_session, recipient, admin)
    assert key2.key_version == 2
    assert key2.status == "ACTIVE"

    # Verify key 1 was marked revoked
    db_session.refresh(key1)
    assert key1.status == "REVOKED"
    assert key1.revoked_at is not None

    # Revoke key 2 explicitly
    RecipientKeyManager.revoke_key(db_session, key2.id, admin)
    db_session.refresh(key2)
    assert key2.status == "REVOKED"
    assert key2.revoked_at is not None

    # Inactive key cannot be retrieved as active
    assert RecipientKeyManager.get_active_key(db_session, recipient.id) is None


def test_production_mode_refuses_default_recipient_kek():
    """Verifies that application refuses to start in production mode if RECIPIENT_KEY_KEK_BASE64 is default or missing."""
    valid_32_bytes = base64.b64encode(os.urandom(32)).decode()

    # Should raise error with default recipient KEK
    with pytest.raises(ValueError, match="CRITICAL: Production deployment requires a secure, non-default RECIPIENT_KEY_KEK_BASE64"):
        Settings(
            ENVIRONMENT="production",
            DOCUMENT_KEK_BASE64=valid_32_bytes,
            RECIPIENT_KEY_KEK_BASE64=DEV_DEFAULT_RECIPIENT_KEK_BASE64,
        )

    # Should succeed with fresh 32-byte keys for both
    settings = Settings(
        ENVIRONMENT="production",
        DOCUMENT_KEK_BASE64=valid_32_bytes,
        RECIPIENT_KEY_KEK_BASE64=valid_32_bytes,
    )
    assert settings.get_recipient_kek_bytes() == base64.b64decode(valid_32_bytes)
