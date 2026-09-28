import re
from typing import Optional, Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Argon2id password hasher with production-grade default parameters
# Argon2id provides state-of-the-art resistance against GPU/ASIC side-channel and brute-force attacks
_ph = PasswordHasher(
    time_cost=3,        # 3 iterations
    memory_cost=65536,  # 64 MiB RAM
    parallelism=4,      # 4 parallel threads
    hash_len=32,
    salt_len=16,
)


def hash_password(plain_password: str) -> str:
    """Hashes a plaintext password using Argon2id with automatic salt generation."""
    if not plain_password or not isinstance(plain_password, str):
        raise ValueError("Password must be a non-empty string")
    return _ph.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against an Argon2id hash using constant-time comparison."""
    if not plain_password or not hashed_password:
        return False
    try:
        return _ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """Enforces strict enterprise password requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special symbol
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[@$!%*?&#^()_\-+=\[\]{}|~`]", password):
        return False, "Password must contain at least one special character."
    return True, None
