"""Authenticator-app codes (RFC 6238) and single-use recovery codes for the owner.

Standard library only. The parameters are the ones authenticator apps expect:
HMAC-SHA1, six digits, thirty-second steps. A code is accepted for the current
step and the step either side of it, and a step that has already opened a
sign-in is never accepted again (replay).

Recovery codes are random, shown once, and stored only as salted scrypt
digests, so a copy of the owner record cannot be used to sign in.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from urllib.parse import quote, urlencode

DIGITS = 6
STEP_SECONDS = 30
WINDOW = 1
SECRET_BYTES = 20

RECOVERY_CODE_COUNT = 10
# No 0, O, 1, I or L: codes are read aloud and typed by hand.
RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # pragma: allowlist secret - a character set, not a secret
_RECOVERY_LENGTH = 8


def new_secret() -> bytes:
    return secrets.token_bytes(SECRET_BYTES)


def encode_secret(raw: bytes) -> str:
    """The secret as base32 text for manual entry, without padding."""
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def decode_secret(text: str) -> bytes:
    """Inverse of :func:`encode_secret`; spaces and lower case are accepted."""
    cleaned = "".join(str(text).split()).upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def hotp(key: bytes, counter: int) -> str:
    """RFC 4226 HOTP: six digits for one counter value."""
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def step_at(now: float) -> int:
    return int(now // STEP_SECONDS)


def totp(key: bytes, now: float) -> str:
    """The code an authenticator app shows at ``now`` (seconds since the epoch)."""
    return hotp(key, step_at(now))


def verify(key: bytes, code: object, *, now: float, last_step: int = 0) -> int | None:
    """The time step ``code`` belongs to, or None when it is not acceptable.

    Accepts the current step and ``WINDOW`` steps either side. A step at or
    before ``last_step`` (the last step accepted for this owner) is refused, so
    one code opens at most one sign-in.
    """
    if not isinstance(code, str) or len(code) != DIGITS or not (code.isascii() and code.isdigit()):
        return None
    current = step_at(now)
    matched = None
    # Every candidate is compared, and the latest matching step is kept.
    for step in range(max(0, current - WINDOW), current + WINDOW + 1):
        if hmac.compare_digest(hotp(key, step), code):
            matched = step
    if matched is None or matched <= last_step:
        return None
    return matched


def otpauth_uri(secret_text: str, account: str, issuer: str = "Lightwork") -> str:
    """The ``otpauth://`` address that authenticator apps read for manual entry."""
    label = quote(f"{issuer}:{account}", safe="@:")
    query = urlencode({"secret": secret_text, "issuer": issuer, "algorithm": "SHA1",
                       "digits": DIGITS, "period": STEP_SECONDS})
    return f"otpauth://totp/{label}?{query}"


def new_recovery_codes() -> list[str]:
    """Ten distinct codes shaped ``XXXX-XXXX``."""
    codes: list[str] = []
    while len(codes) < RECOVERY_CODE_COUNT:
        raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(_RECOVERY_LENGTH))
        code = f"{raw[:4]}-{raw[4:]}"
        if code not in codes:
            codes.append(code)
    return codes


def normalize_recovery(text: object) -> str | None:
    """The eight canonical characters of a typed recovery code, or None."""
    # Text outside ASCII is refused before upper(), which can turn it into ASCII.
    if not isinstance(text, str) or not text.isascii():
        return None
    cleaned = "".join(ch for ch in text.upper() if ch not in " -\t")
    if len(cleaned) != _RECOVERY_LENGTH or any(ch not in RECOVERY_ALPHABET for ch in cleaned):
        return None
    return cleaned


def hash_recovery(canonical: str, salt: bytes) -> str:
    return hashlib.scrypt(canonical.encode("ascii"), salt=salt, n=16384, r=8, p=1, dklen=32).hex()


def new_recovery_entry(code: str) -> dict:
    """The stored form of one recovery code: a random salt and its digest."""
    canonical = normalize_recovery(code)
    if canonical is None:
        raise ValueError("not a recovery code")
    salt = secrets.token_bytes(16)
    return {"salt": salt.hex(), "hash": hash_recovery(canonical, salt)}


def recovery_index(entries: list, code: object) -> int | None:
    """Position of the unused entry that ``code`` opens, or None.

    Every entry is compared, so the time taken does not show which one matched.
    """
    canonical = normalize_recovery(code)
    if canonical is None:
        return None
    found = None
    for index, entry in enumerate(entries):
        digest = hash_recovery(canonical, bytes.fromhex(entry["salt"]))
        if hmac.compare_digest(digest, entry["hash"]) and found is None:
            found = index
    return found
