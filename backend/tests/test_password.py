import pytest
from app.security.password import (
    hash_password,
    verify_password,
    validate_password_strength,
)


def test_argon2id_hashing_and_verification():
    """Verify that hash_password uses Argon2id and generates distinct hashes for identical passwords."""
    raw_password = "P@ssw0rdEnterprise2026!"
    hash1 = hash_password(raw_password)
    hash2 = hash_password(raw_password)

    # Hashes must start with argon2id algorithm identifier
    assert hash1.startswith("$argon2id$")
    assert hash2.startswith("$argon2id$")

    # Due to random salt, hashes must differ
    assert hash1 != hash2

    # Verification must succeed with correct password
    assert verify_password(raw_password, hash1) is True
    assert verify_password(raw_password, hash2) is True

    # Verification must fail with incorrect password
    assert verify_password("WrongPassword123!", hash1) is False
    assert verify_password("", hash1) is False


def test_invalid_hashing_inputs():
    """Verify handling of invalid or empty password inputs."""
    with pytest.raises(ValueError):
        hash_password("")

    assert verify_password("test", "not_a_valid_hash") is False


def test_password_strength_validation():
    """Verify enforcement of enterprise password complexity rules."""
    # Too short (< 12)
    valid, msg = validate_password_strength("Short1!")
    assert valid is False
    assert "at least 12 characters" in msg

    # Missing uppercase
    valid, msg = validate_password_strength("lowercase_only_123!")
    assert valid is False
    assert "uppercase" in msg

    # Missing lowercase
    valid, msg = validate_password_strength("UPPERCASE_ONLY_123!")
    assert valid is False
    assert "lowercase" in msg

    # Missing digit
    valid, msg = validate_password_strength("NoDigitsInThisPassphrase!")
    assert valid is False
    assert "digit" in msg

    # Missing special character
    valid, msg = validate_password_strength("NoSpecialCharIn123Pass")
    assert valid is False
    assert "special character" in msg

    # Valid enterprise password
    valid, msg = validate_password_strength("Secure#Pass2026Platform!")
    assert valid is True
    assert msg is None
