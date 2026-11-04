"""Signed federation envelopes — the shared primitive for instance-to-instance
exchange (signed delegations and trust-plane identity).

An *envelope* is a flat JSON object carrying a ``schema`` tag
(``maverick-<thing>-fed/1``), the sender's ``origin`` name, a ``created_at``
timestamp, and the payload fields. It is signed with this host's audit
Ed25519 key (``maverick.audit.signing`` — the same keypair that signs the
audit chain, stored under ``data_dir("audit", "keys")``):

  - ``pubkey`` / ``key_id``: the signer's raw Ed25519 public key (hex) and
    fingerprint, included in the signed bytes;
  - ``sig``: Ed25519 signature over ``FEDERATION_ENVELOPE_MESSAGE_VERSION +
    b"\\x00" +`` the SHA-256 digest of the canonical JSON (``sort_keys=True``)
    of every field except ``sig``. The digest computation reuses the audit
    chain's canonicalization, but the signed message is domain-separated from
    it (and from detached evidence-export signatures) by the version prefix --
    without it, an envelope signature would be indistinguishable from, and
    replayable as, a signature over an ``audit.signing.AuditSigner`` chain-row
    hash produced under the same key.

Trust model — **fail-closed, pinned keys**: verification only succeeds when
the envelope's ``origin`` appears in the caller's peer map AND the signature
verifies against the *pinned* public key configured for that origin. The
envelope's self-carried ``pubkey`` is never a trust anchor (anyone can mint a
key); it is informational and covered by the signature. An empty peer map
rejects every envelope. A missing ``cryptography`` library also rejects — an
unverifiable envelope is never applied.
"""
from __future__ import annotations

import hashlib
import json
import re

from .constant_time import text_equals

# Origins are lowercase names: no "/", no whitespace, 64 max.
_ORIGIN_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class FederationError(Exception):
    """Raised when an envelope cannot be built (signing unavailable, bad input)."""


def valid_origin(origin: object) -> bool:
    return isinstance(origin, str) and bool(_ORIGIN_RE.fullmatch(origin))


def _digest(payload: dict) -> str:
    """SHA-256 hex of the canonical JSON — same convention as audit chain rows."""
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


# Domain-separated, versioned prefix for the bytes actually signed/verified.
# The digest above intentionally reuses the audit chain row-hash convention,
# but signing the bare digest would make an envelope signature indistinguishable
# from -- and replayable as -- an AuditSigner chain-row signature or a detached
# evidence-export signature produced under the same audit Ed25519 key. This
# prefix is what makes the three uses of that one key cryptographically
# distinct even though all three hash canonical JSON the same way.
FEDERATION_ENVELOPE_MESSAGE_VERSION = "maverick-federation-envelope/v1"


def _envelope_message(digest_hex: str) -> bytes:
    return FEDERATION_ENVELOPE_MESSAGE_VERSION.encode("utf-8") + b"\x00" + bytes.fromhex(digest_hex)


# Envelopes are flat field maps; a legitimate envelope nests a few levels at
# most. A hostile peer can otherwise
# send a deeply-nested object whose canonical-JSON encoding (``_digest`` ->
# ``json.dumps``) recurses until it raises ``RecursionError``, an unauthenticated
# DoS reachable BEFORE signature verification (only the public pinned pubkey
# gates it). Reject anything nested past this bound first.
_MAX_ENVELOPE_DEPTH = 32


def _within_depth(obj: object, limit: int) -> bool:
    """True iff ``obj`` (a parsed JSON value) nests no deeper than ``limit``.

    Iterative (explicit stack) so checking is itself recursion-safe — it can't
    blow the stack on the very input it's meant to screen, and it lets us reject
    a recursion bomb before ``json.dumps`` would hit it.
    """
    stack = [(obj, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > limit:
            return False
        if isinstance(cur, dict):
            for v in cur.values():
                stack.append((v, depth + 1))
        elif isinstance(cur, (list, tuple)):
            for v in cur:
                stack.append((v, depth + 1))
    return True


def sign_envelope(payload: dict) -> dict:
    """Return a signed copy of ``payload`` (adds ``pubkey``/``key_id``/``sig``).

    Signs with this host's audit Ed25519 key (generated on first use). Raises
    :class:`FederationError` when ``cryptography`` is not installed — an
    *unsigned* federation export must never be produced.
    """
    from .audit import signing as audit_signing
    if not audit_signing._have_crypto():
        raise FederationError(
            "cryptography not installed; cannot sign federation envelopes. "
            "Run: python -m pip install -e './packages/maverick-core[audit-signing]'"
        )
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv, pub, key_id = audit_signing._load_or_create_keypair()
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(priv)
    env = dict(payload)
    env.pop("sig", None)
    env["pubkey"] = pub.hex()
    env["key_id"] = key_id
    digest = _digest(env)
    env["sig"] = signer.sign(_envelope_message(digest)).hex()
    return env


def verify_envelope(
    envelope: object, *, expected_schema: str, peers: dict[str, dict]
) -> tuple[bool, str]:
    """Fail-closed envelope verification. Returns ``(ok, reason)``.

    Rejects (never raises) on: non-object envelope, schema mismatch, missing or
    malformed ``origin``, origin absent from ``peers``, envelope pubkey not
    matching the pinned key, missing ``cryptography`` (unverifiable = rejected),
    and signature failure. Verification is against the **pinned** key, so a
    valid signature under an attacker-minted key never passes.
    """
    if not isinstance(envelope, dict):
        return False, "envelope is not an object"
    # Reject a recursion-bomb envelope before _digest's json.dumps would recurse
    # into a RecursionError (fail-closed: this function must never raise).
    if not _within_depth(envelope, _MAX_ENVELOPE_DEPTH):
        return False, "envelope nests too deeply"
    if envelope.get("schema") != expected_schema:
        return False, f"unexpected schema {envelope.get('schema')!r}"
    origin = envelope.get("origin")
    if not valid_origin(origin):
        return False, "missing or malformed origin"
    sig = envelope.get("sig")
    pubkey = envelope.get("pubkey")
    if not isinstance(sig, str) or not sig:
        return False, "missing signature"
    if not isinstance(pubkey, str) or not pubkey:
        return False, "missing pubkey"
    peer = peers.get(origin)  # type: ignore[arg-type]
    if peer is None:
        return False, f"origin {origin!r} is not in the peer trust list"
    pinned = str(peer.get("pubkey") or "")
    if not pinned:
        return False, f"no pinned pubkey for origin {origin!r}"
    if not text_equals(pubkey.lower(), pinned.lower()):
        return False, "envelope pubkey does not match the pinned key for this origin"
    from .audit import signing as audit_signing
    if not audit_signing._have_crypto():
        return False, "cryptography not installed; refusing to apply an unverifiable envelope"
    body = {k: v for k, v in envelope.items() if k != "sig"}
    if not audit_signing.verify_ed25519(pinned, sig, _envelope_message(_digest(body))):
        return False, "signature verification failed"
    return True, "ok"


__all__ = [
    "FederationError",
    "sign_envelope",
    "verify_envelope",
    "valid_origin",
    "FEDERATION_ENVELOPE_MESSAGE_VERSION",
]
