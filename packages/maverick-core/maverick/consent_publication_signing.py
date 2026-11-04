"""Ed25519 signatures for published consent settings.

When ``[consent_preferences.publishing] require_signed_publications`` is true,
every publish, restore and withdrawal of a consent banner, preference centre or
privacy notice is signed at publish time, and the public consent service signs
what it serves, so a website that checks signatures can prove the settings came
from this installation unchanged. Unset or false keeps today's unsigned
behaviour exactly.

Key custody follows the privacy modules' pattern (compare the native consent
receipt signer): one installation signing root, from which every workspace gets
its own Ed25519 key (HMAC-SHA256 over the workspace and the root's name), so a
public key trusted by one workspace's website never vouches for another
workspace's settings.

* ``MAVERICK_CONSENT_PUBLICATION_SIGNING_KEY`` (32 or more bytes, written as
  ``hex:`` or ``base64:`` or plain text) wins when set, and then the key cannot
  be replaced in the app.
* Otherwise the root is the one a global administrator generated on the
  Banner and Preference Center page, stored sealed with the deployment key in
  the dashboard settings overlay (``[consent_publication_signing] keyring``).
  Replaced roots are kept (sealed, at most :data:`MAX_PREVIOUS_ROOTS`) only so
  settings published before a replacement still verify; they never sign.

No private key or root is ever returned, logged or written anywhere else. The
signed messages are canonical JSON statements with their own schema names, so
a publication signature can never be replayed as a served-configuration one.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

ENV = "MAVERICK_CONSENT_PUBLICATION_SIGNING_KEY"
SECTION = "consent_publication_signing"
KEYRING_KEY = "keyring"
MAX_PREVIOUS_ROOTS = 3
ALGORITHM = "Ed25519"
PUBLICATION_SIGNATURE_SCHEMA = "lightwork.consent-publication-signature.v1"
CONFIGURATION_SIGNATURE_SCHEMA = "lightwork.consent-configuration-signature.v1"
PUBLIC_KEY_SCHEMA = "lightwork.consent-publication-key.v1"
_DERIVATION = "lightwork.consent-publication.ed25519.v1"
_ROOT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}\Z")


class PublicationSigningUnavailable(RuntimeError):
    """Signing is required but no usable signing key is in custody."""


def signing_required(config: Mapping[str, Any] | None = None) -> bool:
    """True only when ``[consent_preferences.publishing]
    require_signed_publications`` is exactly true (unset keeps signing off)."""
    if config is None:
        try:
            from .config import load_config

            config = load_config()
        except Exception:  # noqa: BLE001 -- an unreadable config keeps signing off
            return False
    consent = config.get("consent_preferences") if isinstance(config, Mapping) else None
    publishing = consent.get("publishing") if isinstance(consent, Mapping) else None
    return isinstance(publishing, Mapping) and publishing.get(
        "require_signed_publications"
    ) is True


def canonical(value: object) -> bytes:
    """The exact bytes that are signed: sorted, compact, ASCII JSON."""
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def fingerprint(public_key_hex: str) -> str:
    """SHA-256 of the raw public key: how people compare keys."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


def key_id_for(public_key_hex: str) -> str:
    return "lwcp-" + fingerprint(public_key_hex)[:24]


def _root_material(value: object) -> bytes | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    try:
        if text.startswith("base64:"):
            material = base64.b64decode(text[7:].encode("ascii"), validate=True)
        elif text.startswith("hex:"):
            material = bytes.fromhex(text[4:])
        else:
            material = text.encode("utf-8")
    except (UnicodeError, binascii.Error, ValueError):
        return None
    return material if 32 <= len(material) <= 4096 else None


@dataclass(frozen=True)
class PublicationSigner:
    """One workspace's Ed25519 key; the private half never leaves this object."""

    key_id: str
    public_key_hex: str
    _seed: bytes

    def sign(self, message: bytes) -> str:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return Ed25519PrivateKey.from_private_bytes(self._seed).sign(message).hex()

    def __repr__(self) -> str:  # never show key material
        return f"PublicationSigner(key_id={self.key_id!r})"


def _derive(root: bytes, root_id: str, tenant_id: str) -> PublicationSigner:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from .paths import canonical_tenant_id

    # One workspace, one key, however its name was spelled on the way in.
    context = f"{_DERIVATION}\0{canonical_tenant_id(tenant_id)}\0{root_id}".encode()
    seed = hmac.new(root, context, hashlib.sha256).digest()
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return PublicationSigner(key_id=key_id_for(public), public_key_hex=public, _seed=seed)


@dataclass(frozen=True)
class SigningCustody:
    """The installation's signing roots: the active one first, then retired ones."""

    roots: tuple[tuple[str, bytes], ...]
    managed_by_server: bool

    def signer_for(self, tenant_id: str) -> PublicationSigner:
        if not self.roots:
            raise PublicationSigningUnavailable(
                "Signed publishing is on but there is no signing key yet. Create one under "
                "Signing key on the Banner and Preference Center page."
            )
        root_id, root = self.roots[0]
        return _derive(root, root_id, tenant_id)

    def trusted_public_keys(self, tenant_id: str) -> frozenset[str]:
        return frozenset(_derive(root, root_id, tenant_id).public_key_hex
                         for root_id, root in self.roots)

    def __repr__(self) -> str:  # never show key material
        return f"SigningCustody(roots={len(self.roots)}, managed_by_server={self.managed_by_server})"


@dataclass(frozen=True)
class SigningPolicy:
    required: bool
    custody: SigningCustody


def _keyring(config: Mapping[str, Any] | None) -> Mapping[str, Any]:
    section = config.get(SECTION) if isinstance(config, Mapping) else None
    ring = section.get(KEYRING_KEY) if isinstance(section, Mapping) else None
    return ring if isinstance(ring, Mapping) else {}


def keyring_roots(ring: Mapping[str, Any]) -> list[tuple[str, bytes]]:
    """Valid ``(root id, root)`` pairs of an (unsealed) keyring, active first."""
    previous = ring.get("previous")
    previous = previous if isinstance(previous, list) else []
    entries = [ring.get("current"), *previous[:MAX_PREVIOUS_ROOTS]]
    roots: list[tuple[str, bytes]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        root_id = entry.get("id")
        material = _root_material(entry.get("root"))
        if isinstance(root_id, str) and _ROOT_ID_RE.fullmatch(root_id) and material:
            roots.append((root_id, material))
    return roots


def custody(global_config: Mapping[str, Any] | None = None) -> SigningCustody:
    """The signing roots: the server's environment key wins over the app's."""
    if global_config is None:
        try:
            from .config import load_global_config

            global_config = load_global_config()
        except Exception:  # noqa: BLE001 -- unreadable settings hold no key
            global_config = {}
    in_app = tuple(keyring_roots(_keyring(global_config)))
    raw = os.environ.get(ENV)
    if not raw:
        return SigningCustody(roots=in_app, managed_by_server=False)
    material = _root_material(raw)
    if material is None:
        # A malformed server key never falls back to the app's key silently.
        return SigningCustody(roots=(), managed_by_server=True)
    # The server's key signs; the app's keys still verify what they signed.
    return SigningCustody(roots=(("server", material), *in_app), managed_by_server=True)


def configured_policy() -> SigningPolicy:
    """What the installation asks for now (read on every publish and serve).

    The key custody is only read while signing is on.
    """
    if not signing_required():
        return SigningPolicy(required=False, custody=SigningCustody(roots=(),
                                                                    managed_by_server=False))
    return SigningPolicy(required=True, custody=custody())


# ------------------------------------------------------------- statements
def publication_statement(key_id: str, publication: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": PUBLICATION_SIGNATURE_SCHEMA,
        "algorithm": ALGORITHM,
        "key_id": key_id,
        "property_id": str(publication["property_id"]),
        "publication_id": str(publication["publication_id"]),
        "publication_sha256": str(publication["publication_sha256"]),
    }


def configuration_statement(
    key_id: str,
    *,
    publication_key_id: str,
    property_id: str,
    publication_sha256: str,
    configuration_sha256: str,
    policy_id: str,
    policy_version: int,
    policy_sha256: str,
) -> dict[str, Any]:
    return {
        "schema": CONFIGURATION_SIGNATURE_SCHEMA,
        "algorithm": ALGORITHM,
        "key_id": key_id,
        "publication_key_id": publication_key_id,
        "property_id": property_id,
        "publication_sha256": publication_sha256,
        "configuration_sha256": configuration_sha256,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_sha256": policy_sha256,
    }


def verify(public_key_hex: object, signature_hex: object, message: bytes) -> bool:
    """True only for a well-formed Ed25519 signature over ``message``."""
    if not (isinstance(public_key_hex, str) and _HEX64_RE.fullmatch(public_key_hex)
            and isinstance(signature_hex, str) and _SIGNATURE_RE.fullmatch(signature_hex)):
        return False
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(signature_hex), message
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def public_key_document(signer: PublicationSigner) -> dict[str, str]:
    """What a website is given to check signatures: public material only."""
    return {
        "schema": PUBLIC_KEY_SCHEMA,
        "algorithm": ALGORITHM,
        "key_id": signer.key_id,
        "public_key": signer.public_key_hex,
        "fingerprint": fingerprint(signer.public_key_hex),
    }


__all__ = [
    "ALGORITHM",
    "CONFIGURATION_SIGNATURE_SCHEMA",
    "ENV",
    "KEYRING_KEY",
    "MAX_PREVIOUS_ROOTS",
    "PUBLICATION_SIGNATURE_SCHEMA",
    "PUBLIC_KEY_SCHEMA",
    "SECTION",
    "PublicationSigner",
    "PublicationSigningUnavailable",
    "SigningCustody",
    "SigningPolicy",
    "canonical",
    "configuration_statement",
    "configured_policy",
    "custody",
    "fingerprint",
    "key_id_for",
    "keyring_roots",
    "public_key_document",
    "publication_statement",
    "signing_required",
    "verify",
]
