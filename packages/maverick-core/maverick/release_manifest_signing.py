"""Ed25519 signatures on release manifests, verified offline.

A signed manifest is a JSON object with two extra fields: ``sig``, the Ed25519
signature over the canonical JSON of every other field, and ``key_id``, the
signer's public key hex. :mod:`maverick.release_update` signs and checks its
manifests with these functions, so an air-gapped deployment can authenticate
an update bundle without a network.

A signature that checks out is not enough on its own: the signing key must be
one of the deployment's trusted publisher keys (:func:`trusted_publisher_keys`),
otherwise anyone could sign a manifest with a key of their own.
"""
from __future__ import annotations

import json
import os


def _canonical_json(payload: dict) -> bytes:
    """Canonical JSON for signing and verification: sorted keys, no whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _signed_fields(doc: dict) -> dict:
    """Every field of ``doc`` that the signature covers (all but ``sig``/``key_id``)."""
    return {k: v for k, v in doc.items() if k not in ("sig", "key_id")}


def _release_cfg() -> dict:
    """The ``[release]`` config section (config knob — kernel rule 5)."""
    try:
        from .config import load_config
        return dict(load_config().get("release") or {})
    except Exception:  # pragma: no cover - config unavailable => env/embedded only
        return {}


#: Publisher keys compiled into a build. Empty in this source tree, so a
#: deployment trusts only the keys it configures (``MAVERICK_RELEASE_PUBKEYS`` /
#: ``[release] publisher_pubkeys``).
_EMBEDDED_PUBKEYS: tuple[str, ...] = ()


def trusted_publisher_keys(explicit: list[str] | None = None) -> list[str]:
    """The public keys (lower-case hex) whose release signatures this deployment
    accepts: ``explicit`` when given, else ``MAVERICK_RELEASE_PUBKEYS`` (comma
    separated), then ``[release] publisher_pubkeys``, then the keys embedded in
    the build."""
    if explicit is not None:
        return [k.strip().lower() for k in explicit if k.strip()]
    keys: list[str] = []
    env = os.environ.get("MAVERICK_RELEASE_PUBKEYS", "")
    keys += [k.strip().lower() for k in env.split(",") if k.strip()]
    cfg_keys = _release_cfg().get("publisher_pubkeys") or []
    if isinstance(cfg_keys, str):
        cfg_keys = cfg_keys.split(",")
    keys += [str(k).strip().lower() for k in cfg_keys if str(k).strip()]
    keys += [k.lower() for k in _EMBEDDED_PUBKEYS]
    return keys


def new_publisher_keypair() -> tuple[str, str]:
    """Mint a fresh Ed25519 publisher keypair → (private_hex, public_hex)."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv.private_bytes_raw().hex(), priv.public_key().public_bytes_raw().hex()


def sign_manifest(payload: dict, private_key_hex: str) -> dict:
    """Sign a manifest payload with the publisher private key. Returns the full
    signed document (payload + ``sig`` + ``key_id`` = the signing public key)."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    body = _signed_fields(payload)
    sig = priv.sign(_canonical_json(body)).hex()
    return {**body, "sig": sig, "key_id": priv.public_key().public_bytes_raw().hex()}


def verify_manifest_signature(doc: dict, trusted_pubkeys: list[str]) -> tuple[bool, str]:
    """Verify a signed manifest against a trusted key set. Returns (ok, reason).

    The signing key must be in ``trusted_pubkeys``: a self-consistent signature
    by any other key is refused (``untrusted_key``), and an empty trusted set
    refuses everything (``no_trust_anchor``).

    Never raises: a non-dict ``doc`` (a corrupted file that parses to valid but
    non-object JSON) or a non-string ``key_id`` returns ``(False, "malformed")``.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519
    if not isinstance(doc, dict):
        return False, "malformed"
    sig = doc.get("sig")
    key_id = doc.get("key_id")
    if not sig or not key_id:
        return False, "unsigned"
    if not isinstance(key_id, str):
        return False, "malformed"
    key_id = key_id.lower()
    if not trusted_pubkeys:
        return False, "no_trust_anchor"
    if key_id not in [k.lower() for k in trusted_pubkeys]:
        return False, "untrusted_key"
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_id))
        pub.verify(bytes.fromhex(sig), _canonical_json(_signed_fields(doc)))
    except Exception:
        return False, "bad_signature"
    return True, "ok"


__all__ = [
    "new_publisher_keypair",
    "sign_manifest",
    "trusted_publisher_keys",
    "verify_manifest_signature",
]
