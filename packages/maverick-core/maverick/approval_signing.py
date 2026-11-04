"""Cryptographic human approval for high-blast-radius self-changes.

The governed promotion ladder (:mod:`maverick.self_improvement`) requires a
human at the ``code`` and ``weights`` rungs. A *self-settable boolean*
(``Candidate.approved``) is fine for a dev box, but it is exactly the control a
self-modifying agent could flip on its own. If the agent
can propose the code that runs the gate, a boolean it can also set is not a
control -- it's a suggestion.

This module makes the consent unforgeable and **bound to the exact change**. A
human (or a change-advisory board) signs, out of band, an
:class:`ApprovalRequest` = (candidate id, rung, payload digest) with an Ed25519
key whose PUBLIC half the deployment trusts and whose PRIVATE half never touches
the agent's process. The controller verifies that signature against the trusted
set before the human-approval gate passes. Two properties follow:

  * **Non-forgeable** -- the agent cannot mint a valid signature without the
    approver's offline private key (the reference-monitor principle: the control
    lives outside the surface the agent can rewrite).
  * **Bound to the payload** -- the digest covers the candidate's payload, so an
    approval of a benign diff cannot be replayed onto a swapped malicious one
    (TOCTOU). Change the payload, and the signature no longer verifies.

Posture: human-gated promotions require a valid signature from a startup-pinned
key; a self-settable boolean cannot approve the change. The gate fails **closed**:
missing key material, an
absent ``cryptography`` install, or any verification error means "not approved",
never "approved". Reuses the audit chain's Ed25519 verifier
(:func:`maverick.audit.signing.verify_ed25519`); no new dependency.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# Domain-separated, versioned message prefix so an approval signature can never
# be a valid signature for some other Lightwork artifact (or a future format).
APPROVAL_MESSAGE_VERSION = "maverick-approval-v1"


def payload_digest(payload: object) -> str:
    """Canonical SHA-256 hex of a candidate payload, stable across runs.

    A ``str``/``bytes`` payload -- the common case: a unified-diff patch, a tool
    source string, an adapter ref -- is hashed as its RAW bytes, so the digest
    covers exactly the bytes that get applied and agrees with what the creation
    sites record (``sha256(patch.encode())``). A structured payload falls back to
    canonical sorted-key JSON, and a non-serialisable one to ``repr``, so it
    still gets a deterministic digest rather than raising. Either way the digest
    is a pure function of the payload, reproducible by both the offline signer
    and the gate -- which is what makes it a sound binding."""
    if isinstance(payload, str):
        blob = payload.encode("utf-8")
    elif isinstance(payload, (bytes, bytearray)):
        blob = bytes(payload)
    else:
        try:
            blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        except (TypeError, ValueError):
            blob = repr(payload).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def key_id(pubkey_hex: str) -> str:
    """Short fingerprint of an approver public key (the approver identity in the
    audit line). Matches the audit-signing key-id convention: sha256(pub)[:16]."""
    try:
        return hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()[:16]
    except ValueError:
        return "invalid"


@dataclass(frozen=True)
class ApprovalRequest:
    """The exact bytes an approver signs to authorise one promotion."""

    candidate_id: str
    rung: str
    payload_sha256: str

    def message(self) -> bytes:
        """Domain-separated canonical message. Any field change invalidates a
        prior signature -- consent is bound to *this* candidate + *this* payload."""
        return "|".join((
            APPROVAL_MESSAGE_VERSION,
            self.candidate_id,
            self.rung,
            self.payload_sha256,
        )).encode("utf-8")

    @classmethod
    def for_candidate(cls, candidate: object) -> ApprovalRequest:
        """Build the request for a ``self_improvement.Candidate``.

        The digest is ALWAYS recomputed from the candidate's actual ``payload``
        when one is present -- never taken from the self-reported
        ``payload_sha256`` field. That field is an independent, agent-settable
        attribute; trusting it let a valid signature over a benign digest be
        replayed onto a swapped malicious ``payload`` (the payload it carried was
        never hashed), which silently defeats the whole point of the signature.
        Binding to the real payload restores the guarantee in this module's
        docstring: change the payload, and a prior signature stops verifying. A
        self-reported digest that disagrees with the real payload is a tamper
        signal -- it is logged and discarded, not honoured. The stored field is
        only consulted when there is no payload to hash (a digest-only request)."""
        payload = getattr(candidate, "payload", None)
        reported = getattr(candidate, "payload_sha256", None)
        if payload is not None:
            digest = payload_digest(payload)
            if reported and str(reported) != digest:
                log.warning(
                    "approval: candidate %s payload_sha256 %s does not match the "
                    "actual payload digest %s -- binding the approval to the real "
                    "payload so a swapped payload cannot inherit a prior signature",
                    str(getattr(candidate, "id", "")), str(reported)[:12], digest[:12])
        elif reported:
            digest = str(reported)
        else:
            digest = payload_digest(None)
        return cls(
            candidate_id=str(getattr(candidate, "id", "")),
            rung=str(getattr(candidate, "rung", "")),
            payload_sha256=str(digest),
        )


def sign_request(request: ApprovalRequest, private_key_hex: str) -> str:
    """Sign an approval request; returns the hex Ed25519 signature.

    Operator/CAB side, intended to run OFF the agent host (the point is that the
    private key never enters the agent's process). Raises ImportError if
    ``cryptography`` is absent and ValueError on a malformed key -- signing is an
    explicit operator action, so it surfaces errors rather than failing silent."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return priv.sign(request.message()).hex()


def _verify_ed25519(pubkey_hex: str, sig_hex: str, message: bytes) -> bool:
    """Thin wrapper over the audit verifier that fails closed if crypto is
    unavailable (rather than propagating ImportError into the gate)."""
    try:
        from .audit.signing import verify_ed25519
    except Exception:  # pragma: no cover -- audit module import guarded defensively
        return False
    try:
        return bool(verify_ed25519(pubkey_hex, sig_hex, message))
    except ImportError:
        # cryptography not installed: cannot verify -> not approved (fail closed).
        return False
    except Exception:  # pragma: no cover -- any verifier error => not approved
        return False


def verify(
    request: ApprovalRequest,
    signature_hex: str,
    trusted_pubkeys: list[str] | None = None,
) -> str | None:
    """Return the approver ``key_id`` whose key validates the signature, or None.

    Checks the signature against every trusted approver public key; the first
    that verifies identifies the approver. None means no trusted key signed this
    exact (candidate, rung, payload) tuple -- i.e. not approved."""
    if not signature_hex:
        return None
    keys = trusted_approver_keys() if trusted_pubkeys is None else trusted_pubkeys
    msg = request.message()
    for pub_hex in keys:
        if _verify_ed25519(pub_hex, signature_hex, msg):
            return key_id(pub_hex)
    return None


def verify_candidate(candidate: object) -> str | None:
    """Verify a ``Candidate``'s ``approval_signature`` against the trusted set.

    Returns the approver key_id on success, else None. Convenience the
    controller calls; equivalent to ``verify(ApprovalRequest.for_candidate(c),
    c.approval_signature)``."""
    sig = getattr(candidate, "approval_signature", None)
    if not sig:
        return None
    return verify(ApprovalRequest.for_candidate(candidate), str(sig))


def _keys_from_env() -> list[str]:
    from . import _STARTUP_APPROVER_KEYS
    raw = _STARTUP_APPROVER_KEYS
    return [k for k in raw.replace(",", " ").split() if k]


def _keys_from_dir(dir_path: str | None) -> list[str]:
    """Load Ed25519 public keys from ``*.pub`` files in a directory, returned as
    hex.

    Accepts the raw 32-byte audit key-dir format (``pub_bytes``, see
    :mod:`maverick.audit.signing`) and the legacy 64-character hex text format
    used by earlier approver-key deployments. Non-key files are skipped."""
    if not dir_path:
        return []
    try:
        entries = sorted(Path(dir_path).expanduser().glob("*.pub"))
    except OSError:  # pragma: no cover -- a missing dir just yields no keys
        return []
    out: list[str] = []
    for pub in entries:
        try:
            raw = pub.read_bytes()
        except OSError:
            continue
        if len(raw) == 32:
            out.append(raw.hex())
            continue
        try:
            decoded = bytes.fromhex(raw.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError):
            continue
        if len(decoded) == 32:
            out.append(decoded.hex())
    return out


def _config_approval() -> dict:
    """The normalised ``[self_improvement]`` section via config.get_self_improvement,
    which owns the ``approver_keys`` / ``approver_keys_dir`` /
    ``require_signed_approval`` schema (one documented home for the section)."""
    from .config import config_source_errors, get_self_improvement

    cfg = get_self_improvement()
    if config_source_errors() or cfg.get("approval_policy_valid") is not True:
        raise RuntimeError("approver trust policy is unavailable or invalid")
    return cfg


def _trusted_approver_keys(cfg: dict) -> list[str]:
    """Resolve trusted keys from one already-validated policy snapshot."""
    # The process startup environment is the trust root. Config files and key
    # directories writable by the service identity cannot independently grant
    # approval authority, even if they can request stricter enforcement.
    keys = list(_keys_from_env())
    return list(dict.fromkeys(k for k in keys if k))


def trusted_approver_keys() -> list[str]:
    """The deployment's trusted approver public keys (hex), de-duplicated.

    ``MAVERICK_APPROVER_KEYS`` is supplied by the deployment supervisor. Mutable
    configuration and directory contents do not establish trust.
    Empty (the default) means no cryptographic approval is configured."""
    cfg = _config_approval()
    return _trusted_approver_keys(cfg)


def trusted_global_approver_keys() -> list[str]:
    """Resolve only deployment-owned approver roots, never tenant overlays.

    Tenant configuration may narrow or opt into model-improvement behavior, but
    it cannot nominate a key that becomes its own promotion trust anchor.
    The startup environment supplies the trust roots.
    """
    from .config import config_source_errors, load_global_config

    snapshot = load_global_config()
    if config_source_errors():
        raise RuntimeError("global approver trust policy is unavailable or invalid")
    raw = snapshot.get("self_improvement", {})
    if not isinstance(raw, dict):
        raise RuntimeError("global approver trust policy is unavailable or invalid")
    raw_keys = raw.get("approver_keys", [])
    if (
        not isinstance(raw_keys, list)
        or any(not isinstance(value, str) for value in raw_keys)
    ):
        raise RuntimeError("global approver trust policy is unavailable or invalid")
    raw_dir = raw.get("approver_keys_dir")
    if raw_dir is not None and not isinstance(raw_dir, str):
        raise RuntimeError("global approver trust policy is unavailable or invalid")
    if (
        "require_signed_approval" in raw
        and not isinstance(raw.get("require_signed_approval"), bool)
    ):
        raise RuntimeError("global approver trust policy is unavailable or invalid")
    # Validate legacy configuration, but never allow mutable file contents to
    # add a key to the trusted startup environment.
    for raw_key in raw_keys:
        try:
            if len(bytes.fromhex(raw_key.strip())) != 32:
                raise ValueError("invalid key length")
        except ValueError as exc:
            raise RuntimeError("global approver trust policy contains a malformed key") from exc
    keys = list(_keys_from_env())
    normalized: list[str] = []
    for raw_key in keys:
        key = raw_key.strip().lower()
        try:
            decoded = bytes.fromhex(key)
        except ValueError as exc:
            raise RuntimeError(
                "global approver trust policy contains a malformed key",
            ) from exc
        if len(decoded) != 32 or len(key) != 64:
            raise RuntimeError(
                "global approver trust policy contains a malformed key",
            )
        if key not in normalized:
            normalized.append(key)
    return normalized


def signing_enforced() -> bool:
    """Require signatures at human-gated rungs, including before provisioning."""
    _config_approval()  # Invalid policy must still surface as unavailable.
    return True


__all__ = [
    "APPROVAL_MESSAGE_VERSION",
    "ApprovalRequest",
    "payload_digest",
    "key_id",
    "sign_request",
    "verify",
    "verify_candidate",
    "trusted_approver_keys",
    "trusted_global_approver_keys",
    "signing_enforced",
]
