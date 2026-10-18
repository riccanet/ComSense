"""Two-factor sign-in: authenticator app codes (TOTP, RFC 6238), emailed codes and recovery codes.

Users turn methods on from their Account page; Settings > Security decides which methods are
allowed and who must use one. Secrets and codes are stored as follows:

* TOTP secret: encrypted with a key derived from CSFM_SECRET_KEY. A code's time step is
  remembered, so the same code cannot be used twice.
* Recovery codes: ten one-time codes, stored hashed, shown once when generated.
* Email codes: six digits, kept hashed in the signed session for ten minutes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
from urllib.parse import quote, urlencode

from ..models import Role, User
from ..security import hash_secret
from .appsettings import SecuritySettings, decrypt_secret, encrypt_secret

ISSUER = "ComSense"
TOTP_PERIOD = 30
TOTP_DIGITS = 6
EMAIL_CODE_TTL = 600
RECOVERY_CODE_COUNT = 10

METHOD_LABELS = {"totp": "Authenticator app", "email": "Email code"}


# ----------------------------------------------------------------------- TOTP


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    secret = secret.strip().replace(" ", "").upper()
    return base64.b32decode(secret + "=" * (-len(secret) % 8))


def totp_code(secret: str, step: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**TOTP_DIGITS).zfill(TOTP_DIGITS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // TOTP_PERIOD)


def match_totp(secret: str, code: str, last_step: int = 0, now: float | None = None) -> int | None:
    """Return the time step the code belongs to (one step of clock drift either way), or None.

    Steps at or before last_step are refused, so a code works only once.
    """
    code = "".join(c for c in code if c.isdigit())
    if len(code) != TOTP_DIGITS:
        return None
    step = current_step(now)
    for candidate in (step, step - 1, step + 1):
        if candidate > last_step and hmac.compare_digest(totp_code(secret, candidate), code):
            return candidate
    return None


def provisioning_uri(secret: str, username: str) -> str:
    label = quote(f"{ISSUER}:{username}")
    query = urlencode({"secret": secret, "issuer": ISSUER, "digits": TOTP_DIGITS, "period": TOTP_PERIOD})
    return f"otpauth://totp/{label}?{query}"


def qr_svg(data: str) -> str:
    """The data as an inline SVG QR code (no scripts or inline styles, so the CSP allows it)."""
    import segno

    out = io.BytesIO()
    segno.make(data, error="m").save(
        out, kind="svg", xmldecl=False, nl=False, border=2, scale=5, dark="#000", light="#fff",
        svgclass="qr", lineclass=None,
    )
    return out.getvalue().decode()


def stored_secret(user: User, secret_key: str) -> str:
    return decrypt_secret(secret_key, user.totp_secret)


def enable_totp(user: User, secret: str, step: int, secret_key: str) -> None:
    user.totp_secret = encrypt_secret(secret_key, secret)
    user.totp_enabled = True
    user.totp_last_step = step


def verify_user_totp(user: User, code: str, secret_key: str) -> bool:
    if not user.totp_enabled:
        return False
    secret = stored_secret(user, secret_key)
    if not secret:
        return False
    step = match_totp(secret, code, user.totp_last_step or 0)
    if step is None:
        return False
    user.totp_last_step = step
    return True


# ------------------------------------------------------------- recovery codes


def _normalize_recovery(code: str) -> str:
    return "".join(c for c in code.lower() if c.isalnum())


def new_recovery_codes(user: User) -> list[str]:
    """Replace the user's recovery codes; returns the new codes in clear text (show once)."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    codes = ["".join(secrets.choice(alphabet) for _ in range(10)) for _ in range(RECOVERY_CODE_COUNT)]
    user.recovery_codes = [hash_secret(c) for c in codes]
    return [f"{c[:5]}-{c[5:]}" for c in codes]


def use_recovery_code(user: User, code: str) -> bool:
    digest = hash_secret(_normalize_recovery(code))
    stored = list(user.recovery_codes or [])
    for i, item in enumerate(stored):
        if hmac.compare_digest(item, digest):
            del stored[i]
            user.recovery_codes = stored
            return True
    return False


# --------------------------------------------------------------- email codes


def new_email_code() -> tuple[str, dict]:
    """A six-digit code and the record to keep in the session (hashed, with its expiry)."""
    code = f"{secrets.randbelow(10**6):06d}"
    return code, {"hash": hash_secret(code), "expires": time.time() + EMAIL_CODE_TTL}


def check_email_code(record: dict | None, code: str) -> bool:
    if not record or time.time() > float(record.get("expires", 0)):
        return False
    code = "".join(c for c in code if c.isdigit())
    return len(code) == 6 and hmac.compare_digest(hash_secret(code), str(record.get("hash", "")))


# --------------------------------------------------------------------- policy


def mfa_required(user: User, sec: SecuritySettings) -> bool:
    return sec.mfa_required == "all" or (sec.mfa_required == "admins" and user.role == Role.admin)


def allowed_methods(sec: SecuritySettings, email_ready: bool) -> list[str]:
    methods = []
    if sec.allow_totp:
        methods.append("totp")
    if sec.allow_email and email_ready:
        methods.append("email")
    return methods


def user_methods(user: User, sec: SecuritySettings, email_ready: bool) -> list[str]:
    """Methods this user has turned on and may use right now."""
    usable = allowed_methods(sec, email_ready)
    methods = []
    if user.totp_enabled and "totp" in usable:
        methods.append("totp")
    if user.mfa_email_enabled and user.email and "email" in usable:
        methods.append("email")
    return methods


def clear_mfa(user: User) -> None:
    user.totp_secret = ""
    user.totp_enabled = False
    user.totp_last_step = 0
    user.mfa_email_enabled = False
    user.recovery_codes = []
