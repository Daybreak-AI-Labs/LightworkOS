"""JWT inspector (decode + validate, offline).

Decodes a JSON Web Token's header and claims, checks the time-based claims
(``exp`` / ``nbf``) against ``now`` with optional leeway, and — when a shared
secret is supplied — verifies an HMAC (HS256/384/512) signature. Asymmetric algs
(RS*/ES*) are decoded but reported as unverifiable here; an ``alg: none`` token
is flagged as insecure. Pure stdlib (base64/json/hmac) — deterministic and
offline; it never fetches keys or calls the network.

ops:
  - inspect(token, [now], [secret], [leeway])  — reports the algorithm, the
    standard claims, the time validity, and the signature status, with an
    overall VALID / INVALID / UNVERIFIED verdict.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import time
from typing import Any

from . import Tool

_HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


_B64URL_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_ASYMMETRIC_ALGS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                              "ES256", "ES384", "ES512", "ES256K", "EdDSA"})


def _b64url_decode(seg: str) -> bytes:
    # urlsafe_b64decode silently drops characters outside the alphabet, so a
    # tampered segment would still decode (and a signature still verify).
    # Some issuers emit "=" padding; accept it, then require the alphabet.
    seg = seg.rstrip("=")
    if not set(seg) <= _B64URL_CHARS:
        raise binascii.Error("non-base64url character")
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _numeric_date(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) else None


def _inspect(token: str, now: float, secret: str | None, leeway: float) -> str:
    parts = token.split(".")
    if len(parts) != 3:
        return "ERROR: token must have 3 dot-separated segments"
    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return "ERROR: header/payload is not valid base64url-encoded JSON"
    if not isinstance(claims, dict) or not isinstance(header, dict):
        return "ERROR: header and payload must both be JSON objects"

    alg = str(header.get("alg", "?"))

    # --- time validity ---
    time_issues = []
    exp = _numeric_date(claims.get("exp"))
    nbf = _numeric_date(claims.get("nbf"))
    for name in ("exp", "nbf"):
        if name in claims and _numeric_date(claims[name]) is None:
            time_issues.append(f"{name} is not a numeric date")
    if exp is not None and now > exp + leeway:
        time_issues.append(f"EXPIRED {int(now - exp)}s ago")
    if nbf is not None and now < nbf - leeway:
        time_issues.append(f"NOT_YET_VALID in {int(nbf - now)}s")
    time_ok = not time_issues

    # --- signature ---
    if alg == "none":
        sig_state, sig_ok = "INSECURE (alg=none, unsigned)", False
    elif secret is None:
        sig_state, sig_ok = "unverified (no secret given)", None
    elif alg in _HMAC_ALGS:
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected = hmac.new(secret.encode(), signing_input, _HMAC_ALGS[alg]).digest()
        try:
            got = _b64url_decode(parts[2])
        except binascii.Error:
            got = b""
        sig_ok = hmac.compare_digest(expected, got)
        sig_state = "VALID" if sig_ok else "INVALID"
    elif alg in _ASYMMETRIC_ALGS:
        sig_state, sig_ok = f"unverifiable here (asymmetric alg {alg})", None
    else:
        sig_state, sig_ok = f"unverifiable here (unrecognised alg {alg})", None

    # --- verdict ---
    if sig_ok is False or not time_ok:
        verdict = "INVALID"
    elif sig_ok is True:
        verdict = "VALID"
    else:
        verdict = "UNVERIFIED"

    lines = [f"{verdict}: alg={alg}"]
    std = [c for c in ("iss", "sub", "aud", "exp", "nbf", "iat", "jti") if c in claims]
    if std:
        lines.append("claims: " + ", ".join(f"{c}={claims[c]}" for c in std))
    extra = [c for c in claims if c not in ("iss", "sub", "aud", "exp", "nbf", "iat", "jti")]
    if extra:
        lines.append(f"custom claims: {', '.join(sorted(map(str, extra)))}")
    lines.append(f"time: {'valid' if time_ok else '; '.join(time_issues)}")
    lines.append(f"signature: {sig_state}")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "inspect"):
        return f"ERROR: unknown op {args.get('op')!r}"
    token = args.get("token")
    if not isinstance(token, str) or not token:
        return "ERROR: token must be a non-empty JWT string"
    now = args.get("now")
    now = time.time() if now is None else now
    try:
        now = float(now)
    except (TypeError, ValueError):
        return "ERROR: now must be a number (epoch seconds)"
    leeway = args.get("leeway", 0)
    try:
        leeway = float(leeway)
    except (TypeError, ValueError):
        return "ERROR: leeway must be a number (seconds)"
    if leeway < 0:
        return "ERROR: leeway must be >= 0"
    secret = args.get("secret")
    if secret is not None and not isinstance(secret, str):
        return "ERROR: secret must be a string"
    return _inspect(token, now, secret, leeway)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["inspect"]},
        "token": {"type": "string", "description": "the JWT (header.payload.signature)"},
        "now": {"type": "number", "description": "epoch seconds to evaluate exp/nbf against; defaults to system time"},
        "secret": {"type": "string", "description": "HMAC shared secret to verify an HS256/384/512 signature"},
        "leeway": {"type": "number", "description": "clock-skew tolerance in seconds (default 0)"},
    },
    "required": ["token"],
}


def jwt_inspect() -> Tool:
    return Tool(
        name="jwt_inspect",
        description=(
            "Decode and validate a JWT offline. op=inspect with 'token', optional "
            "'now' (epoch), 'secret' (verify HS256/384/512 HMAC), and 'leeway'. "
            "Reports the algorithm, standard + custom claims, time validity "
            "(exp/nbf), and signature status, with an overall VALID/INVALID/"
            "UNVERIFIED verdict. Flags alg=none. Never fetches keys. Deterministic, "
            "offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        # Results can depend on the current wall clock when now is omitted,
        # so this tool must not be treated as cacheable by the output cache.
        parallel_safe=False,
    )
