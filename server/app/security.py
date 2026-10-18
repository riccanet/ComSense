"""Password hashing, token generation and backup encryption."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque

from cryptography.fernet import Fernet

ENROLLMENT_KEY_PREFIX = "csfm_enr_"
DEVICE_TOKEN_PREFIX = "csfm_dev_"

_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, maxmem=64 * 1024 * 1024
    )
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N,
        _SCRYPT_R,
        _SCRYPT_P,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    digest = hashlib.scrypt(
        password.encode(),
        salt=base64.b64decode(salt_b64),
        n=int(n),
        r=int(r),
        p=int(p),
        maxmem=64 * 1024 * 1024,
    )
    return hmac.compare_digest(digest, base64.b64decode(digest_b64))


def hash_secret(secret: str) -> str:
    """Hash a high-entropy machine secret (enrollment key, device token) for storage.

    These secrets are 256-bit random values, so a fast hash is sufficient: there is
    nothing to brute force, and lookups by hash stay constant time.
    """
    return hashlib.sha256(secret.encode()).hexdigest()


def generate_enrollment_key() -> str:
    return ENROLLMENT_KEY_PREFIX + secrets.token_urlsafe(32)


def generate_device_token() -> str:
    return DEVICE_TOKEN_PREFIX + secrets.token_urlsafe(48)


def key_display_prefix(key: str) -> str:
    return key[: len(ENROLLMENT_KEY_PREFIX) + 6]


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_matches(expected: str | None, supplied: str | None) -> bool:
    return bool(expected) and bool(supplied) and hmac.compare_digest(expected, supplied)


class BackupCipher:
    def __init__(self, key: str):
        self._fernet = Fernet(key.encode() if isinstance(key, str) else key)

    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self._fernet.decrypt(data)


def generate_fernet_key() -> str:
    return Fernet.generate_key().decode()


class RateLimiter:
    """Small in-process sliding window limiter, keyed by client address."""

    def __init__(self, limit: int, window_seconds: float):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()
