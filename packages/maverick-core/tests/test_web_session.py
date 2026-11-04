"""Unit tests for the stdlib signed-session cookie (maverick.web_session).

These pin the security properties the dashboard browser-login flow relies on:
a correctly-signed, unexpired cookie round-trips; ANY tampering, expiry, or
wrong key yields ``None`` (never an authenticated payload, never an exception).
No network, no crypto library — pure stdlib HMAC.
"""
from __future__ import annotations

import json
import time

from maverick.web_session import sign_session, verify_session

SECRET = "test-session-secret-0123456789"  # pragma: allowlist secret


def _payload(exp_offset: int = 3600, **extra) -> dict:
    p = {"sub": "user-123", "exp": int(time.time()) + exp_offset}
    p.update(extra)
    return p


def test_round_trip_returns_payload():
    cookie = sign_session(_payload(), SECRET)
    got = verify_session(cookie, SECRET)
    assert got is not None
    assert got["sub"] == "user-123"
    assert "exp" in got


def test_round_trip_preserves_extra_fields():
    cookie = sign_session(_payload(role="admin", n=7), SECRET)
    got = verify_session(cookie, SECRET)
    assert got is not None
    assert got["role"] == "admin"
    assert got["n"] == 7


def test_tampered_payload_returns_none():
    """Flipping a byte in the payload segment invalidates the MAC."""
    cookie = sign_session(_payload(), SECRET)
    body, sig = cookie.split(".")
    bad_body = ("A" if body[0] != "A" else "B") + body[1:]
    assert verify_session(f"{bad_body}.{sig}", SECRET) is None


def test_tampered_signature_returns_none():
    cookie = sign_session(_payload(), SECRET)
    body, sig = cookie.split(".")
    bad_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    assert verify_session(f"{body}.{bad_sig}", SECRET) is None


def test_expired_returns_none():
    cookie = sign_session(_payload(exp_offset=-1), SECRET)
    assert verify_session(cookie, SECRET) is None


def test_expiry_boundary_with_injected_now():
    """exp must be strictly greater than now: exp == now is expired."""
    exp = 1_000_000
    cookie = sign_session({"sub": "u", "exp": exp}, SECRET)
    assert verify_session(cookie, SECRET, now=exp - 1) is not None
    assert verify_session(cookie, SECRET, now=exp) is None
    assert verify_session(cookie, SECRET, now=exp + 1) is None


def test_wrong_secret_returns_none():
    cookie = sign_session(_payload(), SECRET)
    assert verify_session(cookie, "a-different-secret") is None


def test_garbage_returns_none():
    for junk in ("", "not-a-cookie", "a.b.c", ".", "x.", ".y", "!!!.???"):
        assert verify_session(junk, SECRET) is None


def test_non_string_inputs_return_none():
    assert verify_session(None, SECRET) is None  # type: ignore[arg-type]
    cookie = sign_session(_payload(), SECRET)
    assert verify_session(cookie, "") is None
    assert verify_session(cookie, None) is None  # type: ignore[arg-type]


def test_missing_exp_returns_none():
    """A correctly-signed payload with no exp is still rejected."""
    cookie = sign_session({"sub": "u"}, SECRET)
    assert verify_session(cookie, SECRET) is None


def test_non_numeric_exp_returns_none():
    cookie = sign_session({"sub": "u", "exp": "soon"}, SECRET)
    assert verify_session(cookie, SECRET) is None


def test_bool_exp_rejected():
    """A bool exp (True == 1) must not pass the numeric check."""
    cookie = sign_session({"sub": "u", "exp": True}, SECRET)
    assert verify_session(cookie, SECRET) is None


def test_non_object_payload_returns_none():
    """A validly-signed but non-dict JSON payload is rejected."""
    import base64

    raw = json.dumps([1, 2, 3], separators=(",", ":")).encode()
    body = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    # Re-sign the array so the MAC is valid; verify must still reject it.
    import hashlib
    import hmac

    sig = base64.urlsafe_b64encode(
        hmac.new(SECRET.encode(), raw, hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    assert verify_session(f"{body}.{sig}", SECRET) is None


def test_signature_is_constant_length_b64url():
    """Sanity: signature segment is the b64url of a 32-byte SHA256 digest."""
    cookie = sign_session(_payload(), SECRET)
    _, sig = cookie.split(".")
    # 32 bytes -> 43 b64url chars (no padding).
    assert len(sig) == 43
