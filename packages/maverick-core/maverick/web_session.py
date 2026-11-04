"""Stdlib-only signed session cookies for the dashboard's browser login.

The built-in OIDC browser-login flow (``maverick.oidc.login_enabled``) needs a
way to remember "this browser already completed SSO" across requests. The usual
answer is a signed cookie, but Starlette's ``SessionMiddleware`` /
``itsdangerous`` are NOT in Lightwork's dependency graph and adding them would
violate the "no new top-level dependencies" rule. So we sign the cookie
ourselves with the standard library only (``hmac``/``hashlib``/``secrets``/
``base64``/``json``/``time``).

Format (a deliberately tiny, JWT-shaped two-segment token)::

    b64url(json(payload)) "." b64url(hmac_sha256(secret, json_bytes))

The payload is opaque JSON carrying at least ``{"sub": str, "exp": int}``. The
signature covers the *exact* JSON bytes that were encoded, so an attacker can't
re-serialize the payload differently and keep the MAC valid.

Security properties (load-bearing — this is the only thing standing between a
forged cookie and an authenticated session):

- The MAC is HMAC-SHA256 over the encoded payload bytes, keyed by the
  deployment's ``session_secret``. Without the secret a payload can't be signed.
- Verification recomputes the MAC and compares with :func:`hmac.compare_digest`
  (constant-time) to avoid a timing side-channel on the signature.
- Expiry is enforced: a structurally-valid, correctly-signed cookie whose
  ``exp`` is in the past is rejected.
- :func:`verify_session` NEVER raises on malformed input — any garbage (wrong
  shape, bad base64, non-JSON, missing fields, wrong secret, expired) returns
  ``None``. Callers treat ``None`` as "not authenticated" and fall through.

This module touches no network, no config, and no FastAPI — it's pure functions
over ``str``/``dict`` so it can be exhaustively unit-tested in isolation.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

__all__ = ["sign_session", "verify_session"]


def _b64url_encode(raw: bytes) -> str:
    """URL-safe base64 without padding (the JWT segment convention)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    """Inverse of :func:`_b64url_encode`; re-adds the stripped ``=`` padding.

    Raises on invalid base64 — callers in this module catch broadly and map a
    failure to ``None`` (never an exception to the request path).
    """
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _mac(payload_bytes: bytes, secret: str) -> str:
    """HMAC-SHA256 of the encoded-payload bytes, b64url-encoded."""
    digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    return _b64url_encode(digest)


def sign_session(payload: dict, secret: str) -> str:
    """Serialize and HMAC-sign a session ``payload`` into a cookie value.

    The returned string is ``b64url(json(payload)).b64url(hmac_sha256(...))``.
    ``payload`` is expected to carry at least ``{"sub": str, "exp": int}`` (the
    caller owns setting ``exp``); this function does not inspect or mutate it.

    ``json.dumps`` uses sorted keys + compact separators so the exact bytes are
    deterministic — verification re-signs *these* bytes, never a re-serialized
    copy, so the round-trip is stable regardless of dict insertion order.
    """
    payload_bytes = json.dumps(
        payload, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    body = _b64url_encode(payload_bytes)
    sig = _mac(payload_bytes, secret)
    return f"{body}.{sig}"


def verify_session(cookie: str, secret: str, *, now: float | None = None) -> dict | None:
    """Verify a signed session ``cookie`` and return its payload, or ``None``.

    Returns the decoded payload dict ONLY when all of:
      - the cookie is well-formed (exactly two ``.``-separated b64url segments),
      - the recomputed HMAC matches the cookie's signature (constant-time), and
      - the payload parses as a JSON object with an integer/float ``exp`` that
        is strictly greater than ``now`` (defaults to ``time.time()``).

    On ANY failure — wrong shape, bad base64, non-JSON, non-object payload,
    missing/non-numeric ``exp``, signature mismatch, wrong secret, expiry —
    returns ``None``. It never raises on bad input; an unauthenticated caller
    cannot distinguish *why* a cookie was rejected, and the request path stays
    clean.
    """
    if not isinstance(cookie, str) or not isinstance(secret, str) or not secret:
        return None
    # Exactly two segments. A strict 2-part split rejects malformed/3-part
    # tokens (and an empty string, which splits to a single part).
    parts = cookie.split(".")
    if len(parts) != 2:
        return None
    body, sig = parts
    if not body or not sig:
        return None

    try:
        payload_bytes = _b64url_decode(body)
    except (ValueError, TypeError):
        return None

    expected_sig = _mac(payload_bytes, secret)
    # Constant-time compare: never short-circuit on the first differing byte, so
    # the signature can't be recovered via a timing oracle.
    if not hmac.compare_digest(expected_sig.encode(), sig.encode()):
        return None

    try:
        payload = json.loads(payload_bytes)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    exp = payload.get("exp")
    # Reject a bool masquerading as an int (``True == 1``) and any non-number.
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return None

    current = time.time() if now is None else now
    if exp <= current:
        return None

    return payload
