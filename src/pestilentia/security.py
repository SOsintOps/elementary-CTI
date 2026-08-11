# Authentication primitives for the v0.7 multi-user plan: fixed role
# hierarchy and argon2id password hashing. Pure functions only — no web,
# no models, importable from anywhere without layering violations.
from enum import StrEnum

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError


class UserRole(StrEnum):
    USER = "user"
    ANALYST = "analyst"
    ADMIN = "admin"


_ROLE_ORDER: dict[UserRole, int] = {
    UserRole.USER: 0,
    UserRole.ANALYST: 1,
    UserRole.ADMIN: 2,
}

# argon2-cffi defaults are the RFC 9106 low-memory profile (argon2id).
_hasher = PasswordHasher()


def role_at_least(role: str, minimum: str) -> bool:
    """True if `role` grants at least `minimum`. Unknown values never qualify."""
    try:
        return _ROLE_ORDER[UserRole(role)] >= _ROLE_ORDER[UserRole(minimum)]
    except ValueError:
        return False


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Constant-time verify; False on mismatch or malformed hash, never raises."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when the stored hash predates the current argon2 parameters."""
    return _hasher.check_needs_rehash(password_hash)
