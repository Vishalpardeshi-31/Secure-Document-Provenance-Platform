"""Cryptographic key architecture hardening tests.

Validates:
1. Document encryption (AES-256-GCM, AAD binding, tampering detection).
2. Recipient DEK wrapping (ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM).
3. Multi-recipient cryptographic isolation & single DEK consistency.
4. Key lifecycle (ACTIVE -> RETIRED -> REVOKED) and rotation behavior.
5. Version dispatching (Version 1 legacy server envelope vs Version 2 recipient-wrapped).
6. Nonce uniqueness and CSPRNG randomness.
7. Recipient private key protection at rest using Argon2id + AES-256-GCM.
8. Comprehensive tampering resistance across all cryptographic envelope fields.
9. Startup cryptographic self-check validation.
"""
import io
import os
import base64
import pytest
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import mlkem
from app.crypto import (
    AESGCMService,
    MLKEMService,
    HKDFService,
    HashService,
    KeyProtectionService,
    RecipientWrappedKeyManagement,
    LegacyServerEnvelopeKeyManagement,
    KeyManagementService,
    build_document_aad,
    build_dek_wrap_kdf_info,
    build_dek_wrap_aad,
    verify_crypto_primitives,
    WrappedDEKEnvelope,
    ProtectedPrivateKeyMaterial,
)
from app.models.user import User
from app.models.role import UserRole
from app.models.document import Document
from app.models.document_recipient import DocumentRecipient
from app.models.recipient_key import RecipientKey
from app.security.recipient_key_manager import RecipientKeyManager
from app.services.document_service import DocumentService
from app.services.decryption_service import DecryptionService
from app.services.user_service import UserService
from app.security.tokens import create_access_token


# ==============================================================================
# 1. Document Encryption & Canonical AAD Binding
# ==============================================================================

def test_document_encryption_roundtrip_with_canonical_aad():
    """Verify AES-256-GCM document encryption/decryption round-trip with canonical AAD."""
    dek = AESGCMService.generate_key()
    assert len(dek) == 32

    plaintext = b"Strategic Directive: Highly Classified Defense Document Content"
    doc_id = "doc-alpha-123"
    ver_id = "1"
    proto_ver = "SDP-CRYPTO-V2"

    aad = build_document_aad(document_id=doc_id, document_version_id=ver_id, protocol_version=proto_ver)
    assert aad == b"SDP-CRYPTO-V2|DOC|doc-alpha-123|1"

    encrypted = AESGCMService.encrypt(key=dek, plaintext=plaintext, associated_data=aad)
    assert len(encrypted.nonce) == 12
    assert len(encrypted.ciphertext_and_tag) == len(plaintext) + 16
    assert plaintext not in encrypted.ciphertext_and_tag

    decrypted = AESGCMService.decrypt(
        key=dek,
        nonce=encrypted.nonce,
        ciphertext_and_tag=encrypted.ciphertext_and_tag,
        associated_data=aad,
    )
    assert decrypted == plaintext


def test_document_encryption_fails_with_wrong_dek():
    """Verification must fail if decrypted with an incorrect DEK."""
    dek1 = AESGCMService.generate_key()
    dek2 = AESGCMService.generate_key()
    plaintext = b"Payload with strict confidentiality requirements"
    aad = build_document_aad(document_id="doc-1", document_version_id="1")

    encrypted = AESGCMService.encrypt(key=dek1, plaintext=plaintext, associated_data=aad)

    with pytest.raises(ValueError, match="authentication failed"):
        AESGCMService.decrypt(
            key=dek2,
            nonce=encrypted.nonce,
            ciphertext_and_tag=encrypted.ciphertext_and_tag,
            associated_data=aad,
        )


def test_document_encryption_fails_on_tampered_ciphertext():
    """Modifying even a single bit in the ciphertext causes immediate authentication failure."""
    dek = AESGCMService.generate_key()
    plaintext = b"Integrity Protected Strategic Plan"
    aad = build_document_aad(document_id="doc-1", document_version_id="1")

    encrypted = AESGCMService.encrypt(key=dek, plaintext=plaintext, associated_data=aad)
    tampered_ct = bytearray(encrypted.ciphertext_and_tag)
    tampered_ct[0] ^= 0x01  # Flip one bit

    with pytest.raises(ValueError, match="authentication failed"):
        AESGCMService.decrypt(
            key=dek,
            nonce=encrypted.nonce,
            ciphertext_and_tag=bytes(tampered_ct),
            associated_data=aad,
        )


def test_document_encryption_fails_on_tampered_tag():
    """Modifying the trailing GCM authentication tag causes immediate failure."""
    dek = AESGCMService.generate_key()
    plaintext = b"Integrity Protected Strategic Plan"
    aad = build_document_aad(document_id="doc-1", document_version_id="1")

    encrypted = AESGCMService.encrypt(key=dek, plaintext=plaintext, associated_data=aad)
    tampered_ct = bytearray(encrypted.ciphertext_and_tag)
    tampered_ct[-1] ^= 0x01  # Flip one bit in authentication tag

    with pytest.raises(ValueError, match="authentication failed"):
        AESGCMService.decrypt(
            key=dek,
            nonce=encrypted.nonce,
            ciphertext_and_tag=bytes(tampered_ct),
            associated_data=aad,
        )


def test_document_encryption_fails_on_tampered_aad():
    """Transposing ciphertext to another document_id, version, or protocol version fails closed."""
    dek = AESGCMService.generate_key()
    plaintext = b"Sensitive Intelligence Report"
    aad_original = build_document_aad(document_id="doc-1", document_version_id="1", protocol_version="SDP-CRYPTO-V2")

    encrypted = AESGCMService.encrypt(key=dek, plaintext=plaintext, associated_data=aad_original)

    # Attempt 1: Transposed document ID
    aad_wrong_doc = build_document_aad(document_id="doc-2", document_version_id="1", protocol_version="SDP-CRYPTO-V2")
    with pytest.raises(ValueError, match="authentication failed"):
        AESGCMService.decrypt(dek, encrypted.nonce, encrypted.ciphertext_and_tag, aad_wrong_doc)

    # Attempt 2: Replayed across versions
    aad_wrong_ver = build_document_aad(document_id="doc-1", document_version_id="2", protocol_version="SDP-CRYPTO-V2")
    with pytest.raises(ValueError, match="authentication failed"):
        AESGCMService.decrypt(dek, encrypted.nonce, encrypted.ciphertext_and_tag, aad_wrong_ver)

    # Attempt 3: Modified protocol version
    aad_wrong_proto = build_document_aad(document_id="doc-1", document_version_id="1", protocol_version="SDP-CRYPTO-V1")
    with pytest.raises(ValueError, match="authentication failed"):
        AESGCMService.decrypt(dek, encrypted.nonce, encrypted.ciphertext_and_tag, aad_wrong_proto)


# ==============================================================================
# 2. Recipient DEK Wrapping (ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM)
# ==============================================================================

def test_recipient_dek_wrapping_roundtrip():
    """Validates ML-KEM-768 encapsulation, HKDF derivation, and AES-256-GCM DEK unwrap."""
    priv, pub = MLKEMService.generate_key_pair()
    pub_bytes = MLKEMService.serialize_public_key(pub)
    assert len(pub_bytes) == 1184

    original_dek = AESGCMService.generate_key()

    envelope = RecipientWrappedKeyManagement.wrap_dek_for_recipient(
        dek=original_dek,
        recipient_public_key_bytes=pub_bytes,
        document_id="doc-777",
        document_version_id="1",
        recipient_user_id="user-888",
        recipient_key_id="key-999",
        recipient_key_version=1,
    )

    assert len(envelope.kem_ciphertext) == 1088
    assert len(envelope.wrap_nonce) == 12
    assert len(envelope.wrapped_dek) == 32 + 16  # 32-byte DEK + 16-byte tag
    assert envelope.kem_algorithm == "ML-KEM-768"
    assert envelope.kdf_algorithm == "HKDF-SHA-256"
    assert envelope.wrap_algorithm == "AES-256-GCM"
    assert envelope.protocol_version == "SDP-CRYPTO-V2"

    recovered_dek = RecipientWrappedKeyManagement.unwrap_dek_for_recipient(
        envelope=envelope,
        recipient_priv=priv,
        document_id="doc-777",
        document_version_id="1",
        recipient_user_id="user-888",
    )
    assert recovered_dek == original_dek


def test_recipient_dek_unwrap_fails_with_wrong_private_key():
    """Recipient B cannot unwrap a DEK enveloped for Recipient A."""
    priv_a, pub_a = MLKEMService.generate_key_pair()
    priv_b, pub_b = MLKEMService.generate_key_pair()

    original_dek = AESGCMService.generate_key()
    pub_a_bytes = MLKEMService.serialize_public_key(pub_a)

    envelope = RecipientWrappedKeyManagement.wrap_dek_for_recipient(
        dek=original_dek,
        recipient_public_key_bytes=pub_a_bytes,
        document_id="doc-100",
        document_version_id="1",
        recipient_user_id="user-a",
        recipient_key_id="key-a-1",
        recipient_key_version=1,
    )

    # Recipient B attempts decapsulation with their own private key
    with pytest.raises(ValueError, match="Cryptographic unwrap failed"):
        RecipientWrappedKeyManagement.unwrap_dek_for_recipient(
            envelope=envelope,
            recipient_priv=priv_b,
            document_id="doc-100",
            document_version_id="1",
            recipient_user_id="user-a",
        )


def test_recipient_dek_unwrap_fails_on_tampered_kem_ciphertext():
    """Modifying the KEM ciphertext prevents recovery of the correct shared secret and fails closed."""
    priv, pub = MLKEMService.generate_key_pair()
    pub_bytes = MLKEMService.serialize_public_key(pub)
    original_dek = AESGCMService.generate_key()

    envelope = RecipientWrappedKeyManagement.wrap_dek_for_recipient(
        dek=original_dek,
        recipient_public_key_bytes=pub_bytes,
        document_id="doc-1",
        document_version_id="1",
        recipient_user_id="user-1",
        recipient_key_id="key-1",
        recipient_key_version=1,
    )

    tampered_kem_ct = bytearray(envelope.kem_ciphertext)
    tampered_kem_ct[42] ^= 0x55

    tampered_envelope = WrappedDEKEnvelope(
        kem_ciphertext=bytes(tampered_kem_ct),
        wrap_nonce=envelope.wrap_nonce,
        wrapped_dek=envelope.wrapped_dek,
        recipient_key_id=envelope.recipient_key_id,
        recipient_key_version=envelope.recipient_key_version,
    )

    with pytest.raises(ValueError, match="Cryptographic unwrap failed"):
        RecipientWrappedKeyManagement.unwrap_dek_for_recipient(
            envelope=tampered_envelope,
            recipient_priv=priv,
            document_id="doc-1",
            document_version_id="1",
            recipient_user_id="user-1",
        )


def test_recipient_dek_unwrap_fails_on_tampered_wrapped_dek():
    """Modifying the wrapped DEK payload causes immediate AES-GCM tag mismatch."""
    priv, pub = MLKEMService.generate_key_pair()
    pub_bytes = MLKEMService.serialize_public_key(pub)
    original_dek = AESGCMService.generate_key()

    envelope = RecipientWrappedKeyManagement.wrap_dek_for_recipient(
        dek=original_dek,
        recipient_public_key_bytes=pub_bytes,
        document_id="doc-1",
        document_version_id="1",
        recipient_user_id="user-1",
        recipient_key_id="key-1",
        recipient_key_version=1,
    )

    tampered_wdek = bytearray(envelope.wrapped_dek)
    tampered_wdek[5] ^= 0xFF

    tampered_envelope = WrappedDEKEnvelope(
        kem_ciphertext=envelope.kem_ciphertext,
        wrap_nonce=envelope.wrap_nonce,
        wrapped_dek=bytes(tampered_wdek),
        recipient_key_id=envelope.recipient_key_id,
        recipient_key_version=envelope.recipient_key_version,
    )

    with pytest.raises(ValueError, match="Cryptographic unwrap failed"):
        RecipientWrappedKeyManagement.unwrap_dek_for_recipient(
            envelope=tampered_envelope,
            recipient_priv=priv,
            document_id="doc-1",
            document_version_id="1",
            recipient_user_id="user-1",
        )


def test_recipient_dek_unwrap_fails_on_tampered_wrap_nonce():
    """Modifying the wrap nonce causes authentication failure."""
    priv, pub = MLKEMService.generate_key_pair()
    pub_bytes = MLKEMService.serialize_public_key(pub)
    original_dek = AESGCMService.generate_key()

    envelope = RecipientWrappedKeyManagement.wrap_dek_for_recipient(
        dek=original_dek,
        recipient_public_key_bytes=pub_bytes,
        document_id="doc-1",
        document_version_id="1",
        recipient_user_id="user-1",
        recipient_key_id="key-1",
        recipient_key_version=1,
    )

    tampered_nonce = bytearray(envelope.wrap_nonce)
    tampered_nonce[0] ^= 0x01

    tampered_envelope = WrappedDEKEnvelope(
        kem_ciphertext=envelope.kem_ciphertext,
        wrap_nonce=bytes(tampered_nonce),
        wrapped_dek=envelope.wrapped_dek,
        recipient_key_id=envelope.recipient_key_id,
        recipient_key_version=envelope.recipient_key_version,
    )

    with pytest.raises(ValueError, match="Cryptographic unwrap failed"):
        RecipientWrappedKeyManagement.unwrap_dek_for_recipient(
            envelope=tampered_envelope,
            recipient_priv=priv,
            document_id="doc-1",
            document_version_id="1",
            recipient_user_id="user-1",
        )


def test_recipient_dek_unwrap_fails_on_tampered_context_identity():
    """Attempting to unwrap an envelope bound to user-1 under user-2 fails closed."""
    priv, pub = MLKEMService.generate_key_pair()
    pub_bytes = MLKEMService.serialize_public_key(pub)
    original_dek = AESGCMService.generate_key()

    envelope = RecipientWrappedKeyManagement.wrap_dek_for_recipient(
        dek=original_dek,
        recipient_public_key_bytes=pub_bytes,
        document_id="doc-1",
        document_version_id="1",
        recipient_user_id="user-1",
        recipient_key_id="key-1",
        recipient_key_version=1,
    )

    with pytest.raises(ValueError, match="Cryptographic unwrap failed"):
        RecipientWrappedKeyManagement.unwrap_dek_for_recipient(
            envelope=envelope,
            recipient_priv=priv,
            document_id="doc-1",
            document_version_id="1",
            recipient_user_id="user-2",  # Different recipient ID
        )


# ==============================================================================
# 3. Recipient Private Key Protection at Rest (Argon2id + AES-256-GCM)
# ==============================================================================

def test_private_key_protection_roundtrip():
    """Validates Argon2id key derivation and AES-256-GCM private key protection."""
    priv, pub = MLKEMService.generate_key_pair()
    auth_secret = "RecipientStrongSecretPhrase2026!"
    user_id = "user-shield-001"
    key_version = 1

    protected = KeyProtectionService.protect_private_key(
        priv=priv,
        auth_secret=auth_secret,
        user_id=user_id,
        key_version=key_version,
    )

    assert protected.kdf_algorithm == "Argon2id"
    assert protected.encryption_algorithm == "AES-256-GCM"
    assert len(bytes.fromhex(protected.kdf_salt)) == 16
    assert len(bytes.fromhex(protected.encryption_nonce)) == 12
    assert protected.encrypted_private_key != ""

    # Verify plaintext seed is never present
    raw_seed = priv.private_bytes_raw()
    assert raw_seed not in base64.b64decode(protected.encrypted_private_key)

    # Recover private key
    recovered_priv = KeyProtectionService.recover_private_key(
        protected=protected,
        auth_secret=auth_secret,
        user_id=user_id,
    )
    assert recovered_priv.private_bytes_raw() == raw_seed


def test_private_key_protection_fails_with_wrong_auth_secret():
    """Deriving with incorrect password fails Argon2id/AES-GCM decryption."""
    priv, pub = MLKEMService.generate_key_pair()
    protected = KeyProtectionService.protect_private_key(
        priv=priv,
        auth_secret="CorrectSecret2026!",
        user_id="user-1",
        key_version=1,
    )

    with pytest.raises(ValueError, match="Failed to decrypt recipient private key"):
        KeyProtectionService.recover_private_key(
            protected=protected,
            auth_secret="WrongSecretAttempt!",
            user_id="user-1",
        )


def test_private_key_protection_fails_on_tampered_seed_ciphertext():
    """Modifying encrypted private key material fails closed."""
    priv, _ = MLKEMService.generate_key_pair()
    protected = KeyProtectionService.protect_private_key(
        priv=priv,
        auth_secret="Password123!",
        user_id="user-1",
        key_version=1,
    )

    tampered_bytes = bytearray(base64.b64decode(protected.encrypted_private_key))
    tampered_bytes[10] ^= 0xAA

    tampered_protected = ProtectedPrivateKeyMaterial(
        encrypted_private_key=base64.b64encode(tampered_bytes).decode("ascii"),
        kdf_algorithm=protected.kdf_algorithm,
        kdf_salt=protected.kdf_salt,
        kdf_parameters=protected.kdf_parameters,
        encryption_algorithm=protected.encryption_algorithm,
        encryption_nonce=protected.encryption_nonce,
        key_version=protected.key_version,
    )

    with pytest.raises(ValueError, match="Failed to decrypt recipient private key"):
        KeyProtectionService.recover_private_key(
            protected=tampered_protected,
            auth_secret="Password123!",
            user_id="user-1",
        )


# ==============================================================================
# 4. Multi-Recipient Isolation & Single DEK Verification
# ==============================================================================

def test_multi_recipient_single_dek_isolation():
    """Verifies: One document -> ONE random DEK -> ONE ciphertext -> independently wrapped DEK per recipient."""
    priv1, pub1 = MLKEMService.generate_key_pair()
    priv2, pub2 = MLKEMService.generate_key_pair()
    priv3, pub3 = MLKEMService.generate_key_pair()

    # Generate document DEK once
    document_dek = AESGCMService.generate_key()
    document_id = "doc-multi-target"
    ver_id = "1"

    # Encrypt document once
    document_content = b"Single Document Content Encrypted Once Across All Recipients"
    doc_aad = build_document_aad(document_id=document_id, document_version_id=ver_id)
    doc_encrypted = AESGCMService.encrypt(key=document_dek, plaintext=document_content, associated_data=doc_aad)

    # Wrap DEK independently for Recipient 1, 2, 3
    env1 = RecipientWrappedKeyManagement.wrap_dek_for_recipient(
        dek=document_dek,
        recipient_public_key_bytes=MLKEMService.serialize_public_key(pub1),
        document_id=document_id,
        document_version_id=ver_id,
        recipient_user_id="rec-1",
        recipient_key_id="k-1",
        recipient_key_version=1,
    )
    env2 = RecipientWrappedKeyManagement.wrap_dek_for_recipient(
        dek=document_dek,
        recipient_public_key_bytes=MLKEMService.serialize_public_key(pub2),
        document_id=document_id,
        document_version_id=ver_id,
        recipient_user_id="rec-2",
        recipient_key_id="k-2",
        recipient_key_version=1,
    )
    env3 = RecipientWrappedKeyManagement.wrap_dek_for_recipient(
        dek=document_dek,
        recipient_public_key_bytes=MLKEMService.serialize_public_key(pub3),
        document_id=document_id,
        document_version_id=ver_id,
        recipient_user_id="rec-3",
        recipient_key_id="k-3",
        recipient_key_version=1,
    )

    # Assert all 3 envelopes have distinct encapsulated keys, nonces, and wrapped ciphertexts
    assert env1.kem_ciphertext != env2.kem_ciphertext
    assert env2.kem_ciphertext != env3.kem_ciphertext
    assert env1.wrap_nonce != env2.wrap_nonce
    assert env2.wrap_nonce != env3.wrap_nonce
    assert env1.wrapped_dek != env2.wrapped_dek
    assert env2.wrapped_dek != env3.wrapped_dek

    # Each authorized recipient can recover the identical single document DEK
    rec_dek1 = RecipientWrappedKeyManagement.unwrap_dek_for_recipient(env1, priv1, document_id, ver_id, "rec-1")
    rec_dek2 = RecipientWrappedKeyManagement.unwrap_dek_for_recipient(env2, priv2, document_id, ver_id, "rec-2")
    rec_dek3 = RecipientWrappedKeyManagement.unwrap_dek_for_recipient(env3, priv3, document_id, ver_id, "rec-3")

    assert rec_dek1 == document_dek
    assert rec_dek2 == document_dek
    assert rec_dek3 == document_dek

    # Each recipient can decrypt the single document ciphertext
    plain1 = AESGCMService.decrypt(rec_dek1, doc_encrypted.nonce, doc_encrypted.ciphertext_and_tag, doc_aad)
    plain2 = AESGCMService.decrypt(rec_dek2, doc_encrypted.nonce, doc_encrypted.ciphertext_and_tag, doc_aad)
    plain3 = AESGCMService.decrypt(rec_dek3, doc_encrypted.nonce, doc_encrypted.ciphertext_and_tag, doc_aad)

    assert plain1 == document_content
    assert plain2 == document_content
    assert plain3 == document_content


# ==============================================================================
# 5. Nonce Generation Security & Randomness
# ==============================================================================

def test_nonce_generation_is_cryptographically_unique():
    """Verifies that nonces are freshly generated 12-byte CSPRNG bytes and never collide."""
    nonces = {AESGCMService.generate_nonce() for _ in range(500)}
    assert len(nonces) == 500
    for n in nonces:
        assert len(n) == 12
        assert isinstance(n, bytes)


# ==============================================================================
# 6. Key Lifecycle & Key Rotation Behavior
# ==============================================================================

def test_key_rotation_and_revocation_lifecycle(db_session):
    """Verifies lifecycle: ACTIVE -> (rotate) -> RETIRED + ACTIVE v2 -> (revoke) -> REVOKED."""
    admin = User(username="admin_life", email="al@agency.gov", password_hash="h1", role=UserRole.ADMIN.value)
    user = User(username="user_life", email="ul@agency.gov", password_hash="h2", role=UserRole.RECIPIENT.value)
    db_session.add_all([admin, user])
    db_session.commit()

    # 1. Provision initial key version 1
    key_v1 = RecipientKeyManager.provision_recipient_key(db_session, user, admin)
    assert key_v1.key_version == 1
    assert key_v1.status == "ACTIVE"
    assert key_v1.activated_at is not None

    # Active key lookup returns v1
    active_key = RecipientKeyManager.get_active_key(db_session, user.id)
    assert active_key.id == key_v1.id

    # 2. Rotate key: v1 transitions to RETIRED, v2 is provisioned as ACTIVE
    key_v2 = RecipientKeyManager.rotate_key(db_session, user, admin)
    assert key_v2.key_version == 2
    assert key_v2.status == "ACTIVE"

    db_session.refresh(key_v1)
    assert key_v1.status == "RETIRED"  # Retired, preserving historical auditability

    # Active key lookup now returns v2
    active_key = RecipientKeyManager.get_active_key(db_session, user.id)
    assert active_key.id == key_v2.id

    # Retired key remains recoverable for authorized historical decryption
    unwrapped_v1 = RecipientKeyManager._unwrap_private_key(key_v1)
    assert unwrapped_v1 is not None

    # 3. Explicitly revoke key v2
    RecipientKeyManager.revoke_key(db_session, key_v2.id, admin)
    db_session.refresh(key_v2)
    assert key_v2.status == "REVOKED"
    assert key_v2.revoked_at is not None

    # Revoked key CANNOT be used for active distribution
    active_key_after_revoke = RecipientKeyManager.get_active_key(db_session, user.id)
    assert active_key_after_revoke is None

    # Unwrapping revoked key is refused
    with pytest.raises(ValueError, match="is REVOKED"):
        RecipientKeyManager._unwrap_private_key(key_v2)


# ==============================================================================
# 7. Protocol Versioning & Phase 3 Backward Compatibility
# ==============================================================================

def test_phase3_legacy_compatibility_path():
    """Phase 3 documents with key_management_version=1 use the legacy server envelope path."""
    server_kek = AESGCMService.generate_key()
    doc_dek = AESGCMService.generate_key()

    # Wrap via LegacyServerEnvelopeKeyManagement
    wrapped_b64 = LegacyServerEnvelopeKeyManagement.wrap_dek(doc_dek, custom_kek=server_kek)
    assert isinstance(wrapped_b64, str)

    # Unwrap via Legacy path
    recovered = LegacyServerEnvelopeKeyManagement.unwrap_dek(wrapped_b64, custom_kek=server_kek)
    assert recovered == doc_dek


def test_new_documents_enforce_version_2(db_session):
    """Uploading a document with recipients strictly produces key_management_version=2 and protocol_version=SDP-CRYPTO-V2."""
    admin = UserService.create_user(db_session, "admin_v2", "av2@agency.gov", "AdminPass123!", UserRole.ADMIN)
    officer = UserService.create_user(db_session, "officer_v2", "ov2@agency.gov", "OfficerPass123!", UserRole.OFFICER)
    recipient = UserService.create_user(db_session, "recipient_v2", "rv2@agency.gov", "RecipientPass123!", UserRole.RECIPIENT)

    RecipientKeyManager.provision_recipient_key(db_session, recipient, admin)

    content = b"Production Class Document - Version 2 Enforcement Test"
    doc = DocumentService.upload_and_encrypt_document(
        db=db_session,
        owner=officer,
        original_filename="version2_test.pdf",
        content=content,
        recipient_ids=[recipient.id],
    )

    assert doc.key_management_version == 2
    assert doc.protocol_version == "SDP-CRYPTO-V2"
    assert doc.encrypted_dek == ""  # No legacy server-side DEK envelope!

    # Verify recipient record
    rec_record = db_session.query(DocumentRecipient).filter(DocumentRecipient.document_id == doc.id).first()
    assert rec_record is not None
    assert rec_record.recipient_key_id is not None
    assert rec_record.kem_algorithm == "ML-KEM-768"
    assert rec_record.kdf_algorithm == "HKDF"
    assert rec_record.kdf_hash == "SHA-256"
    assert rec_record.kdf_info_version == "SDP-DEK-WRAP-v1"
    assert rec_record.wrap_algorithm == "AES-256-GCM"
    assert rec_record.protocol_version == "SDP-CRYPTO-V2"

    # Decrypt document through DecryptionService
    session, decrypted = DecryptionService.request_and_decrypt(
        db=db_session,
        document_id=doc.id,
        user=recipient,
    )
    assert decrypted == content
    assert session.status == "COMPLETED"


# ==============================================================================
# 8. Cryptographic Startup Self-Checks
# ==============================================================================

def test_startup_cryptographic_self_check():
    """Startup self-check confirms all 5 required algorithms are standard and operational."""
    result = verify_crypto_primitives()
    assert result.is_valid is True
    assert "AES-256-GCM" in result.verified_algorithms
    assert "ML-KEM-768" in result.verified_algorithms
    assert "HKDF-SHA-256" in result.verified_algorithms
    assert "Argon2id" in result.verified_algorithms
    assert "SHA-256" in result.verified_algorithms
