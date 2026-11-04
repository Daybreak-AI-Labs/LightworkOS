"""Exact-release, dual-signed admission for a customer signing-identity bridge.

The installed key remains the trust anchor. Proposed keys never authorize
themselves, and this policy never substitutes for Windows publisher validation.
"""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
import time
from pathlib import Path

from .file_lock import atomic_create_text, ensure_private_directory
from .windows_installer_verification import InstallerVerificationError, verify_minisign

MAX_ENVELOPE_BYTES = 65536
MAX_ADMISSION_SECONDS = 30 * 86400
_SHA = re.compile(r"^[a-f0-9]{64}$")
_VERSION = re.compile(r"^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}$")
_SIDE = {"version", "runtime_sha256", "native_sha256", "publisher_thumbprint", "public_key"}
_POLICY = {"schema", "id", "issued_at", "expires_at", "from", "to", "new_installer_sha256", "rollback"}


class IdentityTransitionError(ValueError):
    """The proposed identity bridge has not established its required authority."""


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IdentityTransitionError("The identity transition contains repeated fields.")
        result[key] = value
    return result


def _side(value):
    if not isinstance(value, dict) or set(value) != _SIDE:
        raise IdentityTransitionError("The identity transition release binding is incomplete.")
    if (not isinstance(value["version"], str) or not _VERSION.fullmatch(value["version"])
            or any(not isinstance(value[name], str) or not _SHA.fullmatch(value[name])
                   for name in ("runtime_sha256", "native_sha256"))
            or not isinstance(value["publisher_thumbprint"], str)
            or not re.fullmatch(r"[A-F0-9]{40}", value["publisher_thumbprint"])
            or not isinstance(value["public_key"], str) or not 1 <= len(value["public_key"]) <= 4096):
        raise IdentityTransitionError("The identity transition contains an invalid release identity.")


def parse(value):
    """Return a bounded canonical envelope; neither parsing nor a new key grants trust."""
    try:
        text = value if isinstance(value, str) else canonical(value)
        if len(text.encode("utf-8")) > MAX_ENVELOPE_BYTES:
            raise IdentityTransitionError("The signed identity transition exceeds its size limit.")
        envelope = json.loads(text, object_pairs_hook=_unique)
        if not isinstance(envelope, dict) or set(envelope) != {"policy", "from_signature", "to_signature"}:
            raise IdentityTransitionError("Select a complete dual-signed identity transition.")
        policy = envelope["policy"]
        if not isinstance(policy, dict) or set(policy) != _POLICY or type(policy["schema"]) is not int or policy["schema"] != 1:
            raise IdentityTransitionError("The identity transition schema is unsupported.")
        if (not isinstance(policy["id"], str) or not re.fullmatch(r"[a-f0-9]{32}", policy["id"])
                or type(policy["issued_at"]) is not int or type(policy["expires_at"]) is not int
                or not 0 < policy["expires_at"] - policy["issued_at"] <= MAX_ADMISSION_SECONDS
                or policy["rollback"] != "exact-retained-pair-only"
                or not isinstance(policy["new_installer_sha256"], str)
                or not _SHA.fullmatch(policy["new_installer_sha256"])):
            raise IdentityTransitionError("The identity transition has invalid admission or rollback limits.")
        for name in ("from", "to"):
            _side(policy[name])
        if tuple(map(int, policy["to"]["version"].split("."))) <= tuple(map(int, policy["from"]["version"].split("."))):
            raise IdentityTransitionError("An identity transition must name an exact newer release.")
        if all(policy["from"][name] == policy["to"][name] for name in ("public_key", "publisher_thumbprint")):
            raise IdentityTransitionError("This release has no signing identity transition to review.")
        if any(not isinstance(envelope[name], str) or not 1 <= len(envelope[name]) <= 16384
               for name in ("from_signature", "to_signature")):
            raise IdentityTransitionError("The identity transition signatures are incomplete.")
        return envelope
    except IdentityTransitionError:
        raise
    except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
        raise IdentityTransitionError("The signed identity transition could not be read.") from exc


def verify(value, *, installed: dict, admit: bool = True):
    """Authenticate both keys against the installed, immutable source identity.

    Expiry limits fresh admission. An already admitted exact recovery pair may
    be resumed or rolled back later, while Windows rechecks both MSI signatures.
    """
    envelope = parse(value)
    policy = envelope["policy"]
    if any(policy["from"][name] != installed.get(name) for name in
           ("version", "runtime_sha256", "native_sha256", "public_key")):
        raise IdentityTransitionError("The transition does not match this installed release and trusted key.")
    if admit and not policy["issued_at"] <= time.time() < policy["expires_at"]:
        raise IdentityTransitionError("The identity transition is not currently open for a new admission. Obtain a current reviewed bridge release.")
    try:
        with tempfile.TemporaryDirectory(prefix="lightwork-identity-check-") as temporary:
            directory = ensure_private_directory(Path(temporary))
            document = directory / "policy.json"
            atomic_create_text(document, canonical(policy))
            verify_minisign(document, installed["public_key"], envelope["from_signature"])
            verify_minisign(document, policy["to"]["public_key"], envelope["to_signature"])
    except InstallerVerificationError as exc:
        raise IdentityTransitionError("The identity transition signatures did not verify against both the installed and proposed keys.") from exc
    return envelope


def verify_installers(envelope, *, old: dict, new: dict):
    """Compare independently verified MSI identities with the admitted bridge."""
    policy = envelope["policy"]
    for name, release in (("from", old), ("to", new)):
        expected = policy[name]
        if (release.get("version") != expected["version"]
                or release.get("runtime_sha256") != expected["runtime_sha256"]
                or str(release.get("publisher_thumbprint", "")).upper() != expected["publisher_thumbprint"]):
            raise IdentityTransitionError("The verified installer does not match the reviewed identity transition.")
    if new.get("sha256") != policy["new_installer_sha256"]:
        raise IdentityTransitionError("The staged bridge installer bytes do not match the signed transition.")


def summary(envelope):
    policy = envelope["policy"]
    return {"id": policy["id"], "sha256": digest(envelope), "expires_at": policy["expires_at"],
            "from_version": policy["from"]["version"], "to_version": policy["to"]["version"],
            "from_publisher": policy["from"]["publisher_thumbprint"], "to_publisher": policy["to"]["publisher_thumbprint"],
            "from_key_sha256": hashlib.sha256(policy["from"]["public_key"].encode()).hexdigest(),
            "to_key_sha256": hashlib.sha256(policy["to"]["public_key"].encode()).hexdigest(),
            "rollback": policy["rollback"], "publisher_os_trust_checked": False}
