"""Audit-log Ed25519 signing.

Every audit event line is hashed together with the previous line's
hash (Merkle-style chain). The chain head is signed with an Ed25519
key whose pubkey is stored alongside.

This gives us tamper-evidence: if any historical line is altered,
the chain breaks at that point. The on-disk format stays NDJSON
(append-only), with two extra fields per row:

  - ``prev_hash``: hex-encoded SHA-256 of the previous row's signed bytes
  - ``hash``:      hex-encoded SHA-256 of this row's signed bytes
  - ``sig``:       hex-encoded Ed25519 signature of ``hash``

Key management:
  - First write: a new Ed25519 keypair is generated and saved at
    ``~/.maverick/audit/keys/<keyid>.{key,pub}`` (chmod 600 on the
    private key).
  - Subsequent writes load the most recent key.
  - ``verify_chain()`` walks a file and confirms every signature +
    chain link. Returns a list of any breaks for human review.

Externally-managed key (enterprise key custody): set
``MAVERICK_AUDIT_SIGNING_KEY`` to a raw 32-byte Ed25519 private key (hex or
base64). It then becomes the active signer and is held IN MEMORY ONLY -- the
private key is never written to the local key dir, so the chain's trust anchor
can be custodied in a KMS / HSM / secrets manager and injected at deploy time
instead of generated-and-left on the host. Lightwork consumes and removes this
environment entry the first time audit signing loads, then caches only decoded
key material in memory. Removal only keeps it from child processes: the
process's initial environment stays readable to the same user through
``/proc/<pid>/environ``, so inherited startup environments are not an HSM/KMS
security boundary. The active public key is a verifier trust root; the writable
on-disk marker is not. When rotating external keys, pin retired public keys in
``MAVERICK_AUDIT_TRUSTED_PUBLIC_KEYS`` so old history remains verifiable.

Optional [audit-signing] extra (cryptography>=44.0.1).
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import re
import threading
from collections.abc import Iterable
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..file_lock import (
    atomic_read_bytes,
    atomic_read_text,
    atomic_write_bytes,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from .errors import AuditRefused

log = logging.getLogger(__name__)


# Legacy single-tenant key dir, kept as a module-level attribute for
# back-compat: existing tests monkeypatch ``signing.KEY_DIR`` to isolate keys,
# so every key path is resolved through ``_key_dir()`` which honours that
# override. With no override, ``_key_dir()`` resolves the *tenant-scoped* dir
# via ``data_dir`` so each tenant gets an independent signing key, while the
# no-tenant default stays exactly ``~/.maverick/audit/keys``.
# A non-I/O sentinel preserves the historical public ``KEY_DIR`` test hook
# without resolving config, client binding, tenant state, or storage at import
# time. Pure consumers such as ``verify_ed25519`` must remain usable against an
# offline artifact even when the deployment's active config is unreadable.
_LEGACY_KEY_DIR = Path.home() / ".maverick" / "audit" / "keys"
KEY_DIR = _LEGACY_KEY_DIR


class OffHostSigningRequiredError(AuditRefused):
    """Raised when audit signing must use off-host key material.

    An :class:`~maverick.audit.errors.AuditRefused`, not a bare RuntimeError:
    this is the refusal that fires under the strictest posture the product
    supports, so a caller hardened against the compliance-floor refusal was
    missing exactly the case that matters most.
    """


def _key_dir() -> Path:
    """The active audit signing-key directory.

    Honours a monkeypatched ``KEY_DIR`` (tests pin it for isolation); otherwise
    routes through the tenant-aware path helper so each tenant gets its own key
    chain while the no-tenant default is the legacy ``~/.maverick/audit/keys``.
    """
    if KEY_DIR is not _LEGACY_KEY_DIR:
        return KEY_DIR
    from ..paths import data_dir

    return data_dir("audit", "keys")


_KEY_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_SIG_RE = re.compile(r"^[0-9a-f]{128}$")

# Cross-file tip-ledger: a signed, chained ledger recording each
# completed day-file's tip hash + row count, so deleting or truncating a WHOLE
# day-file is detectable (per-file verify_chain only sees within one file).
ANCHOR_FILENAME = "anchors.ndjson"
ANCHOR_MARKER_FILENAME = ".anchors.required"
# Signed high-water record of the anchor ledger (row count and tip hash, plus
# the latest anchored day). Truncating ``anchors.ndjson`` together with the
# day-files it described leaves a self-consistent shorter ledger; this record,
# signed with the audit key, is what shows the ledger once had more rows.
ANCHOR_HIGHWATER_FILENAME = ".anchors.highwater.json"
_DAY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _is_valid_key_id(key_id: str) -> bool:
    """Key IDs are fixed-width lowercase hex fingerprints."""
    return bool(_KEY_ID_RE.fullmatch(key_id))


def _key_paths_for_id(key_id: str) -> tuple[Path, Path] | tuple[None, None]:
    """Return trusted key paths for key_id, or (None, None) if invalid."""
    if not _is_valid_key_id(key_id):
        return None, None
    key_dir = _key_dir()
    # key_id is fixed-width lowercase hex, so these components cannot traverse.
    # Keep the final path unresolved so ensure_private_file can reject a planted
    # symlink instead of validating only its referent.
    return key_dir / f"{key_id}.pub", key_dir / f"{key_id}.key"


# Env var carrying an externally-managed Ed25519 audit-signing PRIVATE key
# (raw 32-byte key, hex or base64). When set, the key is the active signer and
# is held in memory only -- never written to the local key dir -- so the audit
# chain's trust anchor can live in a KMS / HSM / secrets manager and be injected
# at deploy time rather than generated-and-left on local disk. See
# ``_injected_keypair`` and the module docstring (enterprise key custody).
_SIGNING_KEY_ENV = "MAVERICK_AUDIT_SIGNING_KEY"
_INJECTED_KEYPAIR_UNREAD = object()
_INJECTED_KEYPAIR_INVALID = object()
_INJECTED_KEYPAIR_LOCK = threading.RLock()
_INJECTED_KEYPAIR_CACHE: tuple[bytes, bytes, str] | None | object = (
    _INJECTED_KEYPAIR_UNREAD
)


def _injected_marker_for_id(key_id: str) -> Path | None:
    """Path of the ``.injected`` marker for ``key_id`` (or None if invalid).

    This non-secret legacy marker is inventory only and is not a trust root.
    """
    if not _is_valid_key_id(key_id):
        return None
    return _key_dir() / f"{key_id}.injected"


def _decode_injected_key(raw: str) -> bytes | None:
    """Decode a raw 32-byte Ed25519 private key from hex or base64.

    Returns the 32 key bytes, or None if the encoding is invalid. A configured
    malformed value is rejected by the caller without falling back to disk.
    """
    import base64
    import binascii

    s = raw.strip()
    if not s:
        return None
    # Hex first (64 chars, unambiguous); then base64 (std or urlsafe).
    try:
        b = bytes.fromhex(s)
        if len(b) == 32:
            return b
    except ValueError:
        pass
    padded = s + "=" * (-len(s) % 4)
    # validate=True: a mistyped key with stray characters must be rejected,
    # not silently decoded (characters dropped) into some other key.
    for candidate in (padded, padded.replace("-", "+").replace("_", "/")):
        try:
            b = base64.b64decode(candidate, validate=True)
            if len(b) == 32:
                return b
        except (binascii.Error, ValueError):
            continue
    return None


def _injected_keypair() -> tuple[bytes, bytes, str] | None:
    """Resolve the injected key atomically across concurrent callers."""
    with _INJECTED_KEYPAIR_LOCK:
        return _injected_keypair_unlocked()


def _injected_keypair_unlocked() -> tuple[bytes, bytes, str] | None:
    """Return (priv, pub, key_id) for an env-injected signing key, or None.

    Consumes :data:`_SIGNING_KEY_ENV` once, removes it from ``os.environ`` as
    early as possible, and caches only decoded key material. Removal keeps the
    key out of child processes' environments only: the kernel's copy of the
    initial environment (``/proc/<pid>/environ``) still holds it and stays
    readable to the same user, so inherited startup environments are not an
    HSM/KMS boundary. The caller writes just the public key (+ an ``.injected``
    marker) for inventory; verification trusts the active in-memory public key.
    A malformed or unavailable configured key fails closed.
    """
    global _INJECTED_KEYPAIR_CACHE
    if _INJECTED_KEYPAIR_CACHE is not _INJECTED_KEYPAIR_UNREAD:
        # Late mutation of the process environment cannot replace the active
        # process signer, but it must still be scrubbed immediately. Leaving a
        # raw private key behind would expose it through same-user /proc reads.
        os.environ.pop(_SIGNING_KEY_ENV, None)
        if _INJECTED_KEYPAIR_CACHE is _INJECTED_KEYPAIR_INVALID:
            raise ValueError("configured audit signing key is invalid or unavailable")
        return _INJECTED_KEYPAIR_CACHE

    raw = os.environ.pop(_SIGNING_KEY_ENV, None)
    if not raw:
        _INJECTED_KEYPAIR_CACHE = None
        return None
    # The environment value has been consumed; any error from this point must
    # leave a persistent failure, never appear as an absent configuration.
    _INJECTED_KEYPAIR_CACHE = _INJECTED_KEYPAIR_INVALID
    if not _have_crypto():
        raise ValueError("configured audit signing key is unavailable")
    priv_bytes = _decode_injected_key(raw)
    if priv_bytes is None:
        _INJECTED_KEYPAIR_CACHE = _INJECTED_KEYPAIR_INVALID
        raise ValueError("configured audit signing key is invalid")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = hashlib.sha256(pub_bytes).hexdigest()[:16]
    _INJECTED_KEYPAIR_CACHE = (priv_bytes, pub_bytes, key_id)
    return _INJECTED_KEYPAIR_CACHE


def _reset_injected_keypair_cache() -> None:
    """Test-only: clear the process-global injected-key cache.

    :func:`_injected_keypair` reads ``MAVERICK_AUDIT_SIGNING_KEY`` exactly once
    per process and caches the result (a deliberate security choice: the env var
    is popped so it can't be recovered from ``/proc``). That cache is correct in
    production but leaks across tests in a shared worker: a test that runs audit
    signing with no injected key caches a miss, shadowing a later test that DOES
    set the key. The conftest cache-reset fixture calls this so each test reads
    the key fresh (mirrors client/config/tenant cache resets)."""
    global _INJECTED_KEYPAIR_CACHE
    with _INJECTED_KEYPAIR_LOCK:
        _INJECTED_KEYPAIR_CACHE = _INJECTED_KEYPAIR_UNREAD


def _provision_injected_pubkey(pub: bytes, key_id: str) -> None:
    """Persist the PUBLIC half (+ ``.injected`` marker) of an injected key.

    Writes ``<key_id>.pub`` and an empty ``<key_id>.injected`` marker for
    inventory; neither file establishes trust. Best-effort and
    idempotent: a read-only key dir (e.g. a locked-down container) is tolerated
    -- signing and verification use the active in-memory key.
    """
    try:
        key_dir = ensure_private_directory(_key_dir())
        pub_path = key_dir / f"{key_id}.pub"
        atomic_write_bytes(pub_path, pub, mode=0o644)
        marker = key_dir / f"{key_id}.injected"
        if marker.exists():
            ensure_private_file(marker, 0o600)
        else:
            atomic_write_bytes(marker, b"", mode=0o600)
    except OSError:
        # Never let key-dir provisioning failure break audit signing.
        log.debug("could not persist injected audit pubkey for %s", key_id)


@dataclass
class ChainBreak:
    line_no: int  # 1-indexed
    # 'bad_hash' | 'bad_signature' | 'chain_mismatch' | 'malformed' | 'unsigned'
    # 'unsigned' = the row carries NONE of hash/sig/key_id, i.e. it was written
    # with audit signing disabled (the default) — distinct from 'malformed'
    # (some-but-not-all fields: the vocabulary of real tampering).
    reason: str
    detail: str


def _have_crypto() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401

        return True
    except ImportError:
        return False


def verify_ed25519(pubkey_hex: str, sig_hex: str, message: bytes) -> bool:
    """Return True iff ``sig_hex`` is a valid Ed25519 signature over
    ``message`` under ``pubkey_hex`` (both hex-encoded raw keys/sigs).

    Returns False on any verification failure or malformed input. Raises
    ImportError if ``cryptography`` is not installed -- callers that want
    fail-open behavior must guard with ``_have_crypto()`` first.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pub.verify(bytes.fromhex(sig_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


# Domain-separated, versioned prefix for detached-digest signatures (evidence
# exports). Without this, a detached signature was Ed25519-over-the-raw-32-byte
# digest -- byte-for-byte what AuditSigner.write() signs for a chain row whose
# ``hash`` equals that same digest, and what sign_envelope signed for a
# federation envelope. The same key producing indistinguishable signatures
# across three protocols is a signing oracle: a detached-digest signature
# obtained via evidence export could be replayed as a forged audit-chain row
# (or vice versa) as long as some row's canonical-JSON hash happened to equal
# the exported digest. Prefixing makes the signed bytes structurally
# unable to collide with a bare 32-byte row hash or envelope digest.
DETACHED_DIGEST_MESSAGE_VERSION = "maverick-detached-digest/v1"


def _detached_digest_message(digest_hex: str) -> bytes:
    return DETACHED_DIGEST_MESSAGE_VERSION.encode("utf-8") + b"\x00" + bytes.fromhex(digest_hex)


def sign_detached_digest(digest_hex: str) -> dict[str, str]:
    """Sign one SHA-256 digest with the active audit identity.

    Evidence exports use this detached form so the exported bytes are bound to
    the same rotating Ed25519 trust registry as audit rows without appending an
    artificial event to the operating log.  The caller remains responsible for
    stating whether the key has independent/off-host custody.

    The signed message is domain-separated (:data:`DETACHED_DIGEST_MESSAGE_VERSION`
    prefix + a NUL separator + the raw digest bytes), not the bare digest --
    see :func:`verify_detached_digest`.
    """
    if not isinstance(digest_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", digest_hex):
        raise ValueError("detached audit digest must be lowercase SHA-256 hex")
    if not _have_crypto():
        raise RuntimeError("cryptography is required for detached audit signing")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private_raw, public_raw, key_id = _load_or_create_keypair()
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(private_raw)
    derived = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if derived != public_raw or hashlib.sha256(derived).hexdigest()[:16] != key_id:
        raise ValueError("audit signing identity is inconsistent")
    return {
        "algorithm": "Ed25519-SHA256",
        "digest": digest_hex,
        "key_id": key_id,
        "message_version": DETACHED_DIGEST_MESSAGE_VERSION,
        "signature": signer.sign(_detached_digest_message(digest_hex)).hex(),
    }


def verify_detached_digest(pubkey_hex: str, digest_hex: str, sig_hex: str) -> bool:
    """Verify a signature produced by :func:`sign_detached_digest`.

    Recomputes the same domain-separated message. A signature over the bare
    digest bytes (for example a forged audit-chain row-hash signature, or a
    federation-envelope signature over the same digest) never verifies here,
    and a valid detached-digest signature never verifies as a plain
    ``verify_ed25519(pubkey, sig, bytes.fromhex(digest))`` call either -- that
    cross-protocol reuse is exactly what the prefix rules out.
    """
    if not isinstance(digest_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", digest_hex):
        return False
    if not _have_crypto():
        return False
    return verify_ed25519(pubkey_hex, sig_hex, _detached_digest_message(digest_hex))


def _generate_keypair() -> tuple[bytes, bytes, str]:
    """Return (private_key_bytes, public_key_bytes, key_id)."""
    if not _have_crypto():
        raise ImportError(
            "cryptography not installed. Run: python -m pip install -e './packages/maverick-core[audit-signing]'"
        )
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = hashlib.sha256(pub_bytes).hexdigest()[:16]
    return priv_bytes, pub_bytes, key_id


# Filename of the explicit active-key pointer inside the key dir (see
# _save_keypair). Not a ``*.key``/``*.pub`` so it never matches the key globs.
_ACTIVE_POINTER = "active"


def _active_key_id(key_dir: Path) -> str | None:
    """The explicitly-recorded active key id, or None for a legacy directory.

    A present-but-invalid pointer is security state corruption, not a reason to
    guess from mtimes and possibly reactivate an older key.
    """
    pointer = key_dir / _ACTIVE_POINTER
    try:
        ensure_private_file(pointer, 0o600)
    except FileNotFoundError:
        return None
    kid = atomic_read_text(pointer).strip()
    if not _is_valid_key_id(kid):
        raise ValueError("audit active-key pointer is invalid")
    if not (key_dir / f"{kid}.key").exists() or not (key_dir / f"{kid}.pub").exists():
        raise ValueError("audit active-key pointer names an incomplete keypair")
    return kid


def _save_keypair(priv: bytes, pub: bytes, key_id: str) -> Path:
    if not _is_valid_key_id(key_id) or len(priv) != 32 or len(pub) != 32:
        raise ValueError("invalid audit Ed25519 keypair")
    key_dir = ensure_private_directory(_key_dir())
    priv_path = key_dir / f"{key_id}.key"
    pub_path = key_dir / f"{key_id}.pub"
    # Both files are created with their final ACL/mode before the first key byte
    # is written. In particular, POSIX mode bits passed to os.open are not a
    # Windows DACL; the shared atomic writer uses a create-time protected DACL.
    atomic_write_bytes(priv_path, priv, mode=0o600)
    atomic_write_bytes(pub_path, pub, mode=0o644)
    # Record the active key explicitly. Selection must NOT depend on mtime
    # ordering: two keys minted within the same filesystem mtime tick (coarse
    # FS, or a fast rotate) tie, and ``max(..., key=mtime)`` over a sorted list
    # then keeps the alphabetically-FIRST key -- which may be the OLD one,
    # silently defeating rotation. ``_save_keypair`` always runs for the
    # newest-minted key (initial generate + rotate), so this pointer always
    # names the key that should be active.
    atomic_write_text(key_dir / _ACTIVE_POINTER, key_id, mode=0o600)
    return priv_path


def rotate_audit_keypair() -> str:
    """Mint a fresh Ed25519 signing keypair and make it the active signer.

    Safe and additive: the new key becomes active because it is the most-recent
    ``.key`` (see :func:`_load_or_create_keypair`), while every prior ``<id>.pub``
    is retained so ``verify_chain`` still validates rows signed under old keys
    (each row carries its ``key_id``). No existing audit data is rewritten.

    Returns the new ``key_id``. Takes effect for new :class:`AuditSigner`
    instances (next day-file / process restart); a long-running signer keeps its
    in-memory key until restarted.
    """
    if (_injected_keypair() is not None or os.environ.get(_KMS_WRAPPED_KEY_ENV)
            or require_offhost_signing()):
        raise OffHostSigningRequiredError(
            "Rotate the external signing key in its secret manager and pin the previous public key first"
        )
    key_dir = ensure_private_directory(_key_dir())
    with cross_process_lock(key_dir / _ACTIVE_POINTER):
        priv, pub, key_id = _generate_keypair()
        _save_keypair(priv, pub, key_id)
    return key_id


_KMS_WRAPPED_KEY_ENV = "MAVERICK_AUDIT_SIGNING_KEY_WRAPPED"

# One-time guard so the co-located-key custody warning (emitted when
# _load_or_create_keypair generates a local private key) fires once per process
# rather than on every AuditSigner construction.
_LOCAL_KEY_WARNED = False


def require_offhost_signing() -> bool:
    """Whether signing requires an externally supplied key instead of a disk key.

    On by default under enterprise mode to avoid leaving a generated private
    key on local disk. Injected and KMS-unwrapped keys still sign locally; this
    policy does not establish isolated key custody. Also flips on via ``[audit]
    require_offhost_key`` / ``MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY``. Off by default
    otherwise (the local-key happy path is unchanged)."""
    env = os.environ.get("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "").strip().lower()
    if env in {"1", "true", "yes", "on"}:
        return True
    if env in {"0", "false", "no", "off"}:
        return False
    try:
        from ..config import load_config
        val = ((load_config() or {}).get("audit") or {}).get("require_offhost_key")
        if val is not None:
            return bool(val) if not isinstance(val, str) else val.strip().lower() in {
                "1", "true", "yes", "on"}
    # failure-policy: best_effort
    except Exception:  # pragma: no cover -- config never weakens posture silently
        pass
    try:
        from ..enterprise import enterprise_enabled
        return bool(enterprise_enabled())
    # failure-policy: best_effort
    except Exception:  # pragma: no cover
        return False


def _kms_wrapped_keypair() -> tuple[bytes, bytes, str] | None:
    """Source the signing key from a KMS-wrapped blob, unwrapped into memory.

    ``MAVERICK_AUDIT_SIGNING_KEY_WRAPPED`` (hex/base64 of a KMS-wrapped 32-byte
    Ed25519 private key) + a configured cloud KMS (``[encryption.kms]`` AWS / GCP
    / Vault) keeps the stored private key wrapped and unwraps it into process
    memory at startup -- never written to local disk. This is local signing,
    not an isolated KMS signing operation; the process receives the private key.
    Returns ``(priv, pub, key_id)`` or ``None`` (no config / crypto absent / any
    error -> fall through to the next key source)."""
    raw = os.environ.get(_KMS_WRAPPED_KEY_ENV)
    if not raw or not _have_crypto():
        return None
    import base64
    import binascii
    s = raw.strip()
    wrapped: bytes | None = None
    try:
        wrapped = bytes.fromhex(s)
    except ValueError:
        try:
            wrapped = base64.b64decode(s, validate=True)
        except (binascii.Error, ValueError):
            wrapped = None
    if not wrapped:
        log.warning("%s is set but is not valid hex/base64; ignoring", _KMS_WRAPPED_KEY_ENV)
        return None
    try:
        from ..config import load_config
        from ..kms_backends import build_cloud_kms
        provider = str(((load_config() or {}).get("kms") or {}).get("provider") or "").strip()
        kek = build_cloud_kms(provider)
        priv_bytes = kek.unwrap(wrapped, context=b"maverick-audit-signing")
    # failure-policy: fail_soft_with_audit
    except Exception as e:
        log.warning("audit signing KMS unwrap failed (%s); falling back", e)
        return None
    if len(priv_bytes) != 32:
        log.warning("KMS-unwrapped audit key is %d bytes, expected 32; ignoring",
                    len(priv_bytes))
        return None
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    key_id = hashlib.sha256(pub_bytes).hexdigest()[:16]
    return priv_bytes, pub_bytes, key_id


def active_key_is_offhost() -> bool:
    """Whether the active key is externally supplied rather than stored on disk.

    True when the signer's private key comes from an env-injected key
    (:func:`_injected_keypair`, sourced from a KMS / secrets manager) or a
    KMS-wrapped key (:func:`_kms_wrapped_keypair`) -- it never lives
    generated-and-left on local disk. The historical function name describes
    key sourcing, not the location of signing: both sources expose private key
    bytes to this process. True does not establish a non-exportable signer or
    protection from an actor able to use the process's key. Independently
    retained checkpoints provide a separate history commitment.
    """
    if _injected_keypair() is not None:
        return True
    if _kms_wrapped_keypair() is not None:
        return True
    return False


def _read_disk_keypair(key_dir: Path, key_id: str) -> tuple[bytes, bytes, str]:
    """Read one locally-custodied keypair after ACL and shape validation."""
    pub_path, priv_path = _key_paths_for_id(key_id)
    if pub_path is None or priv_path is None:
        raise ValueError("audit key directory contains an invalid key id")
    ensure_private_file(priv_path, 0o600)
    ensure_private_file(pub_path, 0o644)
    priv = atomic_read_bytes(priv_path)
    pub = atomic_read_bytes(pub_path)
    if len(priv) != 32 or len(pub) != 32:
        raise ValueError("audit Ed25519 key files must each contain 32 raw bytes")
    if hashlib.sha256(pub).hexdigest()[:16] != key_id:
        raise ValueError("audit public key does not match its key id")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:
        raise ValueError(
            "cryptography is required to validate audit signing keys",
        ) from exc
    derived_pub = (
        ed25519.Ed25519PrivateKey.from_private_bytes(priv)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    if derived_pub != pub:
        raise ValueError("audit private/public signing key files do not match")
    return priv, pub, key_id


def _load_or_create_keypair_unlocked() -> tuple[bytes, bytes, str]:
    """Load the most-recent keypair or generate one if none exists.

    Key-source precedence: an env-injected key (:func:`_injected_keypair`) >
    a KMS-wrapped key (:func:`_kms_wrapped_keypair`) > the on-disk key. The first
    two keep the private key off local disk (only the public half is persisted,
    for verification) so the audit chain's trust anchor can live in a KMS / HSM /
    secrets manager. When :func:`require_offhost_signing` is on (enterprise mode)
    and neither external source is available, this RAISES rather than generate a
    local private-key file. In every current path the signer receives private
    key bytes, so this is not an isolated signing-service boundary.
    """
    injected = _injected_keypair()
    if injected is not None:
        priv, pub, key_id = injected
        _provision_injected_pubkey(pub, key_id)
        return priv, pub, key_id

    kms = _kms_wrapped_keypair()
    if kms is not None:
        priv, pub, key_id = kms
        _provision_injected_pubkey(pub, key_id)
        return priv, pub, key_id

    if require_offhost_signing() or os.environ.get(_KMS_WRAPPED_KEY_ENV):
        raise OffHostSigningRequiredError(
            "off-host audit signing is required (enterprise mode / [audit] "
            "require_offhost_key) but no off-host key is configured. Set "
            f"{_SIGNING_KEY_ENV} (a KMS/secrets-manager-sourced Ed25519 key) or "
            f"{_KMS_WRAPPED_KEY_ENV} (a KMS-wrapped key) so the audit signing key "
            "never lives generated-and-left on the local host."
        )

    key_dir = _key_dir()
    if key_dir.exists():
        ensure_private_directory(key_dir)
        # Prefer the explicit active-key pointer (deterministic -- immune to the
        # mtime tie that would otherwise let a rotation silently keep the old
        # key). Fall back to newest-mtime for legacy key dirs written before the
        # pointer existed; use st_mtime_ns there for finer tie resolution.
        active = _active_key_id(key_dir)
        if active is not None:
            return _read_disk_keypair(key_dir, active)
        priv_files = sorted(key_dir.glob("*.key"))
        if priv_files:
            for candidate in priv_files:
                if not _is_valid_key_id(candidate.stem):
                    raise ValueError("audit key directory contains an invalid key filename")
                ensure_private_file(candidate, 0o600)
            latest = max(priv_files, key=lambda p: p.stat().st_mtime_ns)
            key_id = latest.stem
            pub_path = key_dir / f"{key_id}.pub"
            if not pub_path.exists():
                raise ValueError("audit key directory contains an incomplete keypair")
            return _read_disk_keypair(key_dir, key_id)
    # Falling through to a locally generated + saved private key. Be honest about
    # what its custody buys: integrity vs. accidental/non-privileged edits, NOT
    # tamper-evidence against a same-uid actor who can read the key and re-sign.
    global _LOCAL_KEY_WARNED
    if not _LOCAL_KEY_WARNED:
        _LOCAL_KEY_WARNED = True
        log.warning(
            "audit signing: generating a co-located Ed25519 signing key under %s. "
            "A same-uid on-disk key gives integrity against accidental / "
            "non-privileged edits only -- it is NOT tamper-evidence against an "
            "actor running as the maverick uid, who can read the key and cleanly "
            "re-sign the chain. To avoid a private key on local disk, set "
            "%s (a KMS / secrets-manager-sourced Ed25519 key) or %s (a KMS-wrapped "
            "key). Both still expose the private key to the signing process; "
            "use independently retained checkpoints to detect later history changes.",
            key_dir, _SIGNING_KEY_ENV, _KMS_WRAPPED_KEY_ENV,
        )
    priv, pub, key_id = _generate_keypair()
    _save_keypair(priv, pub, key_id)
    return priv, pub, key_id


def _load_or_create_keypair() -> tuple[bytes, bytes, str]:
    """Select a signing key, serializing local first-use provisioning.

    Off-host keys retain their read-only-container behavior. The on-disk path
    uses the stable active-pointer sidecar so simultaneous fleet workers cannot
    observe another worker's private key before its public half and pointer are
    durably published.
    """
    injected = _injected_keypair()
    if injected is not None:
        priv, pub, key_id = injected
        _provision_injected_pubkey(pub, key_id)
        return priv, pub, key_id

    kms = _kms_wrapped_keypair()
    if kms is not None:
        priv, pub, key_id = kms
        _provision_injected_pubkey(pub, key_id)
        return priv, pub, key_id

    if require_offhost_signing() or os.environ.get(_KMS_WRAPPED_KEY_ENV):
        raise OffHostSigningRequiredError(
            "off-host audit signing is required (enterprise mode / [audit] "
            "require_offhost_key) but no off-host key is configured. Set "
            f"{_SIGNING_KEY_ENV} (a KMS/secrets-manager-sourced Ed25519 key) or "
            f"{_KMS_WRAPPED_KEY_ENV} (a KMS-wrapped key) so the audit signing key "
            "never lives generated-and-left on the local host."
        )

    key_dir = ensure_private_directory(_key_dir())
    with cross_process_lock(key_dir / _ACTIVE_POINTER):
        return _load_or_create_keypair_unlocked()


def _prepare_private_audit_file(path: Path) -> None:
    """Privately create or tighten an audit file without a first-writer race."""
    ensure_private_directory(path.parent)
    with cross_process_lock(path):
        try:
            ensure_private_file(path, 0o600)
        except FileNotFoundError:
            atomic_write_bytes(path, b"", mode=0o600)


def _validated_tail_hash(data: object, *, operation: str, path: Path) -> str:
    """Return a structurally valid signed tail hash, or reject corruption.

    A wholly unsigned object is accepted for compatibility when signing is
    enabled on an existing unsigned log. Any partial signing vocabulary is
    suspicious: chaining from an absent or malformed hash would silently reset
    the signed chain after a truncated/tampered tail.
    """
    if not isinstance(data, dict):
        raise ValueError(
            f"audit chain {operation}: last line of {path} must be a JSON object; "
            "refusing to silently restart the chain"
        )
    signed_fields = {"prev_hash", "hash", "sig", "key_id"}
    present = signed_fields.intersection(data)
    if not present:
        return ""
    if present != signed_fields:
        missing = ", ".join(sorted(signed_fields - present))
        raise ValueError(
            f"audit chain {operation}: last line of {path} has incomplete "
            f"signing fields (missing {missing}); refusing to append"
        )
    row_hash = data["hash"]
    prev_hash = data["prev_hash"]
    sig = data["sig"]
    key_id = data["key_id"]
    if not isinstance(row_hash, str) or not _HASH_RE.fullmatch(row_hash):
        raise ValueError(
            f"audit chain {operation}: last line of {path} has an invalid hash"
        )
    if not isinstance(prev_hash, str) or (
        prev_hash != "" and not _HASH_RE.fullmatch(prev_hash)
    ):
        raise ValueError(
            f"audit chain {operation}: last line of {path} has an invalid prev_hash"
        )
    if not isinstance(sig, str) or not _SIG_RE.fullmatch(sig):
        raise ValueError(
            f"audit chain {operation}: last line of {path} has an invalid signature"
        )
    if not isinstance(key_id, str) or not _is_valid_key_id(key_id):
        raise ValueError(
            f"audit chain {operation}: last line of {path} has an invalid key_id"
        )
    return row_hash


_CHAIN_FIELDS = ("prev_hash", "key_id", "hash", "sig")


def _chain_safe_payload(event: dict) -> dict:
    """The row body exactly as a verifier will re-read it.

    A JSON round trip first, so the hashed bytes match what ``verify_chain``
    re-serialises (an integer dict key sorts differently from its string
    form). Then a caller field that shares a chain field's name moves to
    ``payload_<name>``: it would otherwise be overwritten (``key_id``,
    ``prev_hash``) or hashed and then replaced, leaving a row that can never
    verify (``hash``, ``sig``).
    """
    payload = json.loads(json.dumps(event, default=str))
    for name in _CHAIN_FIELDS:
        if name in payload:
            payload[f"payload_{name}"] = payload.pop(name)
    return payload


class AuditSigner:
    """Sign + chain audit log lines.

    Wraps an NDJSON sink, adding ``prev_hash`` / ``hash`` / ``sig`` /
    ``key_id`` fields to each row before writing.

    Thread-safe and cross-process safe. Tail discovery, hash/sign construction,
    and append are serialized under an OS-backed file lock so independent
    service workers cannot fork the chain.
    """

    def __init__(self, audit_path: Path):
        self._lock = threading.Lock()
        self._path = audit_path
        self._priv_bytes, self._pub_bytes, self._key_id = _load_or_create_keypair()
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError as e:
            raise ImportError(
                "cryptography not installed. Run: python -m pip install -e './packages/maverick-core[audit-signing]'"
            ) from e
        self._signer = ed25519.Ed25519PrivateKey.from_private_bytes(self._priv_bytes)
        derived_pub = self._signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if derived_pub != self._pub_bytes:
            raise ValueError("audit private/public signing key files do not match")
        if hashlib.sha256(derived_pub).hexdigest()[:16] != self._key_id:
            raise ValueError("audit signing key does not match its key id")
        _prepare_private_audit_file(self._path)
        self._last_hash = self._resume_last_hash()

    def _resume_last_hash(self) -> str:
        """If the file has prior entries, find the latest hash to chain on.

        A torn final line (crash mid-write, no trailing newline) must NOT
        silently reset the chain to genesis (prev_hash=""), which would let
        an attacker truncate-and-reappend a self-consistent sub-chain that
        verifies clean. If the last non-empty line is unparseable, raise so
        the caller surfaces it instead of starting a fresh chain.
        """
        from .writer import _file_append_lock

        ensure_private_file(self._path, 0o600)
        with open(self._path, "a+b") as f, _file_append_lock(f):
            return self._locked_tail_hash(f, operation="resume")

    def _locked_tail_hash(self, fileobj, *, operation: str = "append") -> str:
        """Read the current on-disk chain tip from an append-locked handle.

        ``AuditSigner`` instances are process-local, but a day file may have
        several writers (dashboard workers, ``serve``, cron jobs). Their cached
        ``_last_hash`` values can therefore be stale even though each instance's
        own thread lock is sound. The append lock must cover both reading the
        real tail and constructing/writing the next row; otherwise two signers
        can append siblings that name the same predecessor and fork the chain.
        """
        # Read backwards in bounded chunks. Scanning the entire day file for
        # every event would make signing quadratic over a long-running day and
        # turn the integrity fix into an availability problem.
        fileobj.seek(0, os.SEEK_END)
        position = fileobj.tell()
        pending = b""
        last_line = b""
        while position > 0 and not last_line:
            size = min(position, 64 * 1024)
            position -= size
            fileobj.seek(position)
            combined = fileobj.read(size) + pending
            lines = combined.splitlines()
            if position > 0:
                pending = lines[0] if lines else combined
                complete_lines = lines[1:]
            else:
                complete_lines = lines
            last_line = next(
                (line for line in reversed(complete_lines) if line.strip()),
                b"",
            )
        if not last_line:
            return ""
        try:
            data = json.loads(last_line)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"audit chain {operation}: last line of {self._path} is unparseable "
                "(torn write?); refusing to silently restart the chain"
            ) from e
        return _validated_tail_hash(data, operation=operation, path=self._path)

    def write(
        self,
        event: dict,
        *,
        idempotency_identity: tuple[str, str] | None = None,
    ) -> bool:
        """Append one signed row, or acknowledge an identical prior identity."""
        with self._lock:
            try:
                from .writer import (
                    _file_append_lock,
                    _locked_event_identity_exists,
                )

                # A deleted/replaced live file is integrity state loss. Do not
                # recreate it at genesis; require an existing private regular
                # file on every append.
                ensure_private_directory(self._path.parent)
                # Whole-file rewriters (GDPR erase, reanchor_file) replace this
                # path via os.replace, which swaps the inode out from under any
                # handle already opened on it. The append lock below is held on
                # that handle, so it cannot serialize against them: a signer
                # that opened the old inode appends into an orphaned file and
                # the row is lost while write() still reports True. This
                # sidecar-keyed lock is the one both sides can share -- take it
                # BEFORE opening, so the handle we get is the surviving inode.
                # Ordering is always sidecar -> append lock; rewriters take only
                # the sidecar, so the two cannot deadlock.
                with cross_process_lock(self._path):
                    ensure_private_file(self._path, 0o600)
                    with open(self._path, "a+b") as f, _file_append_lock(f):
                        # The append lock still covers tail read, hash/sign, and
                        # append as one transaction for independent signers that
                        # may have cached the same old tip and would otherwise
                        # append a cryptographically valid but structurally
                        # forked pair of rows.
                        actual_tail = self._locked_tail_hash(f)
                        payload = _chain_safe_payload(event)
                        if (
                            idempotency_identity is not None
                            and _locked_event_identity_exists(
                                f,
                                payload,
                                idempotency_identity,
                            )
                        ):
                            self._last_hash = actual_tail
                            return True
                        payload["prev_hash"] = actual_tail
                        payload["key_id"] = self._key_id
                        row_bytes = json.dumps(
                            payload, sort_keys=True, default=str
                        ).encode("utf-8")
                        row_hash = hashlib.sha256(row_bytes).hexdigest()
                        payload["hash"] = row_hash
                        payload["sig"] = self._signer.sign(
                            bytes.fromhex(row_hash)
                        ).hex()
                        line = (json.dumps(payload, default=str) + "\n").encode(
                            "utf-8"
                        )
                        # Switching an update-mode stream from reading to writing
                        # requires an intervening seek. O_APPEND still guarantees
                        # that the bytes land at the physical end of the file.
                        f.seek(0, os.SEEK_END)
                        f.write(line)
                        # fsync so a power loss can't lose committed audit rows
                        # (or leave a torn line that breaks chain resume). The
                        # audit log is the trust anchor; durability matters more
                        # than the small write cost here.
                        f.flush()
                        os.fsync(f.fileno())
                ensure_private_file(self._path, 0o600)
                # Only advance the in-memory chain head AFTER the row is
                # durably on disk; otherwise a crash between write and this
                # line would chain the next row on a hash that isn't there.
                self._last_hash = row_hash
                return True
            except OSError as e:
                log.warning("audit signer: write failed: %s", e)
                return False

    @property
    def public_key_hex(self) -> str:
        return self._pub_bytes.hex()


def _segment_text(path: Path) -> str:
    """A day-file's NDJSON text, transparently decrypting an at-rest-sealed segment
    so the verifier works on sealed and plaintext day-files alike.

    Unlike export readers, verification must fail closed: an unreadable or
    undecryptable segment is signed evidence that cannot be proven intact.
    """
    from .sealing import segment_text
    return segment_text(path, fail_soft=False)


def verify_chain(  # noqa: C901 - linear forensic checks stay auditable together
    path: Path,
    pubkey_hex: str | None = None,
    *,
    segment: str | None = None,
    lines: Iterable[str] | None = None,
    max_breaks: int | None = None,
) -> list[ChainBreak]:
    """Walk every line; verify chain links + signatures.

    If ``pubkey_hex`` is None, resolve each row's ``key_id`` from the active
    external key and operator pins, or the local key registry in local mode.

    Returns a list of breaks. Empty list = chain intact. Proof-producing
    callers that already opened a sealed segment may pass its authenticated
    plaintext through ``segment`` so verification and aggregation operate on
    the exact same immutable bytes rather than reading the file twice. ``lines``
    supports bounded caller-owned snapshot iteration; its read failures propagate
    so the caller cannot turn a partial scan into an intact-chain result.
    """
    if max_breaks is not None and (type(max_breaks) is not int or not 1 <= max_breaks <= 1000):
        raise ValueError("max_breaks must be an integer from 1 to 1000")
    if not _have_crypto():
        return [ChainBreak(0, "no_crypto", "cryptography not installed")]
    if pubkey_hex is not None:
        try:
            if not isinstance(pubkey_hex, str) or len(bytes.fromhex(pubkey_hex)) != 32:
                raise ValueError("invalid public key")
        except ValueError:
            return [ChainBreak(0, "no_pubkey", "explicit public key is invalid")]
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    breaks: list[ChainBreak] = []
    if not path.exists():
        return [ChainBreak(0, "missing_file", str(path))]
    prev = ""
    pubkey_cache: dict[str, ed25519.Ed25519PublicKey] = {}
    registry: dict[str, str] | None = None

    def _load_pubkey(key_id: str):
        nonlocal registry
        if key_id in pubkey_cache:
            return pubkey_cache[key_id]
        try:
            if pubkey_hex is not None:
                raw_pub = bytes.fromhex(pubkey_hex)
            else:
                if registry is None:
                    registry = trusted_audit_public_keys()
                public = registry.get(key_id)
                if public is None:
                    return None
                raw_pub = bytes.fromhex(public)
            if len(raw_pub) != 32:
                return None
            obj = ed25519.Ed25519PublicKey.from_public_bytes(raw_pub)
        except (OSError, ValueError):
            return None
        pubkey_cache[key_id] = obj
        return obj

    if lines is not None and segment is not None:
        raise ValueError("supply audit segment or lines, not both")
    if segment is None and lines is None:
        try:
            text = _segment_text(path)
        # failure-policy: fail_closed
        except Exception as e:
            return [ChainBreak(0, "unreadable_segment", str(e))]
    else:
        text = segment

    with (nullcontext(lines) if lines is not None else io.StringIO(text)) as f:
        for n, line in enumerate(f, start=1):
            if max_breaks is not None and len(breaks) >= max_breaks:
                break  # nonempty failure result; never claim the remaining scan passed
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except (ValueError, RecursionError) as e:
                breaks.append(ChainBreak(n, "malformed", str(e)))
                continue
            if not isinstance(data, dict):
                breaks.append(
                    ChainBreak(n, "malformed", "audit row must be a JSON object")
                )
                continue
            row_hash = data.get("hash")
            sig = data.get("sig")
            row_prev = data.get("prev_hash", "")
            key_id = data.get("key_id", "")
            if not row_hash and not sig and not key_id:
                if pubkey_hex is not None or row_prev:
                    # A trusted pubkey means the caller expected signed rows;
                    # an orphaned prev_hash means signing-only chain context is
                    # still present. In either case, all signature fields being
                    # absent is suspicious (for example, stripped signatures),
                    # not an honestly unsigned deployment.
                    breaks.append(ChainBreak(
                        n, "malformed",
                        "missing hash/sig/key_id (possible stripped signature fields)",
                    ))
                else:
                    # Written without signature fields, for example when signing
                    # was explicitly disabled. Signing defaults on; an old
                    # unsigned row does not establish the current setting.
                    breaks.append(ChainBreak(
                        n, "unsigned",
                        "row has no hash/sig/key_id (audit signing disabled)",
                    ))
                continue
            if not row_hash or not sig or not key_id:
                breaks.append(ChainBreak(n, "malformed", "missing hash/sig/key_id"))
                continue
            if not all(
                isinstance(value, str)
                for value in (row_hash, sig, row_prev, key_id)
            ):
                breaks.append(
                    ChainBreak(
                        n,
                        "malformed",
                        "hash/sig/prev_hash/key_id must be strings",
                    )
                )
                continue
            if row_prev != prev:
                breaks.append(
                    ChainBreak(
                        n,
                        "chain_mismatch",
                        f"row prev={row_prev[:12]}... expected {prev[:12] or '(empty)'}",
                    )
                )
            payload_for_hash = {k: v for k, v in data.items() if k not in ("hash", "sig")}
            try:
                expected_hash = hashlib.sha256(
                    json.dumps(payload_for_hash, sort_keys=True, default=str).encode("utf-8")
                ).hexdigest()
            except (ValueError, RecursionError, UnicodeError) as e:
                breaks.append(ChainBreak(n, "malformed", str(e)))
                continue
            if expected_hash != row_hash:
                breaks.append(ChainBreak(n, "bad_hash", "content rehash != row hash"))
            pub = _load_pubkey(key_id)
            if pub is None:
                breaks.append(ChainBreak(n, "no_pubkey", f"key_id {key_id!r}"))
            else:
                try:
                    pub.verify(bytes.fromhex(sig), bytes.fromhex(row_hash))
                except InvalidSignature:
                    breaks.append(ChainBreak(n, "bad_signature", "Ed25519 verify failed"))
                except ValueError as e:
                    # A tampered sig/hash that isn't valid hex must be
                    # flagged as a break, NOT crash the verifier (which
                    # would skip every later row — the opposite of what
                    # a tamper-evidence tool should do).
                    breaks.append(ChainBreak(n, "bad_signature", f"malformed sig/hash: {e}"))
            prev = row_hash
    return breaks


def trusted_audit_public_keys() -> dict[str, str]:
    """Return independently configured or locally held audit public keys.

    When an injected/KMS key is in use, the active key and public keys pinned
    by the operator are the trust roots. Writable on-disk marker files cannot
    add a trusted key. Locally held keys remain supported in local-key mode,
    whose same-uid integrity limitation is documented.
    """
    registry: dict[str, str] = {}
    from .. import _STARTUP_AUDIT_TRUSTED_PUBLIC_KEYS
    for item in _STARTUP_AUDIT_TRUSTED_PUBLIC_KEYS.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            raw = bytes.fromhex(item)
        except ValueError as exc:
            raise ValueError("configured audit public key is invalid") from exc
        if len(raw) != 32:
            raise ValueError("configured audit public key must be 32 bytes")
        registry[hashlib.sha256(raw).hexdigest()[:16]] = raw.hex()

    active = _injected_keypair() or _kms_wrapped_keypair()
    if active is not None:
        _private, public, key_id = active
        registry[key_id] = public.hex()
        return registry
    if registry or require_offhost_signing() or os.environ.get(_KMS_WRAPPED_KEY_ENV):
        return registry

    key_dir = _key_dir()
    if not key_dir.exists():
        return registry
    ensure_private_directory(key_dir)
    try:
        entries = sorted(key_dir.glob("*.pub"))
    except OSError as exc:
        raise ValueError("audit public-key registry is unavailable") from exc
    for public_path in entries:
        key_id = public_path.stem
        if not _is_valid_key_id(key_id):
            raise ValueError("audit public-key registry contains an invalid key id")
        public_path_checked, private_path = _key_paths_for_id(key_id)
        if public_path_checked is None or private_path is None:
            raise ValueError("audit public-key registry contains an invalid path")
        marker = _injected_marker_for_id(key_id)
        if private_path.exists():
            _private, raw, loaded_key_id = _read_disk_keypair(key_dir, key_id)
            if loaded_key_id != key_id:
                raise ValueError(
                    "audit public-key registry contains a mismatched keypair",
                )
        elif marker is not None and marker.exists():
            # Historical injected-key markers are not independently trusted.
            # An operator can pin a retired public key explicitly for rotation.
            continue
        else:
            raise ValueError(
                "audit public-key registry contains an unprovisioned public key",
            )
        if (
            len(raw) != 32
            or hashlib.sha256(raw).hexdigest()[:16] != key_id
        ):
            raise ValueError("audit public-key registry contains a malformed key")
        registry[key_id] = raw.hex()
    return registry


# ---- cross-file tip-ledger -------------------------------------------------

def _file_tip_and_count(path: Path) -> tuple[str, int]:
    """Return ``(last_row_hash, non_empty_row_count)`` for a signed day-file."""
    tip = ""
    count = 0
    with io.StringIO(_segment_text(path)) as f:
        for line in f:
            if not line.strip():
                continue
            count += 1
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                tip = str(data.get("hash") or tip)
    return tip, count


def day_files(audit_dir: Path) -> list[Path]:
    """Date-named day-files (YYYY-MM-DD.ndjson), excluding the anchor ledger.

    The single definition of "what counts as an audit day-file"; the read-side
    consumers (export / dsar / soc2) reach it via :mod:`maverick.audit.reader`.
    """
    try:
        return sorted(
            p for p in audit_dir.iterdir() if p.suffix == ".ndjson" and _DAY_RE.fullmatch(p.stem)
        )
    except FileNotFoundError:
        return []


def _anchored_days(audit_dir: Path) -> set[str]:
    path = audit_dir / ANCHOR_FILENAME
    days: set[str] = set()
    if not path.exists():
        return days
    with io.StringIO(_segment_text(path)) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(d, dict):
                continue
            if d.get("kind") == "anchor" and d.get("day"):
                days.add(str(d["day"]))
    return days


def _anchor_marker_path(audit_dir: Path) -> Path:
    """Return the durable marker that records an expected anchor ledger.

    The marker prevents a deleted ``anchors.ndjson`` from being silently
    recreated from only the day-files that an attacker chose to leave behind.
    """
    return audit_dir / ANCHOR_MARKER_FILENAME


def _mark_anchor_ledger_required(audit_dir: Path) -> None:
    marker = _anchor_marker_path(audit_dir)
    try:
        ensure_private_directory(audit_dir)
        if marker.exists():
            ensure_private_file(marker, 0o600)
        else:
            atomic_write_text(
                marker,
                "anchors.ndjson is required for audit tamper-evidence\n",
                mode=0o600,
            )
    except OSError as e:  # pragma: no cover - best-effort marker
        log.warning("audit anchors: failed to write ledger marker: %s", e)


def _ensure_anchor_ledger(audit_dir: Path) -> bool:
    """Return whether it is safe to append to the anchor ledger.

    A missing ledger is acceptable before the first completed day is anchored.
    Once the marker records that the ledger has existed, however, a missing
    ledger is suspicious and must not be rebuilt from only the remaining
    day-files.
    """
    anchor_path = audit_dir / ANCHOR_FILENAME
    if anchor_path.exists():
        _mark_anchor_ledger_required(audit_dir)
        return True
    return not _anchor_marker_path(audit_dir).exists()


def _append_anchor(audit_dir: Path, day: str, tip_hash: str, row_count: int) -> bool:
    """Append one signed, chained anchor row to the tip-ledger."""
    if not _have_crypto():
        return False
    signer = AuditSigner(audit_dir / ANCHOR_FILENAME)
    ok = bool(
        signer.write({
            "kind": "anchor",
            "day": day,
            "tip_hash": tip_hash,
            "row_count": row_count,
            "ts": datetime.now(timezone.utc).isoformat(),
        })
    )
    if ok:
        _mark_anchor_ledger_required(audit_dir)
        _write_anchor_highwater(audit_dir)
    return ok


# The marker text once a high-water record has been written. From then on a
# missing record is a break; before it (an installation upgraded from a
# version without the record) its absence is accepted until the next anchor.
_HIGHWATER_MARKER_TEXT = (
    "anchors.ndjson and .anchors.highwater.json are required for audit tamper-evidence\n"
)


def _ledger_rows(anchor_path: Path) -> list[dict]:
    """The anchor ledger's non-empty rows, in order (unparseable rows as ``{}``)."""
    rows: list[dict] = []
    with open(anchor_path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                d = {}
            rows.append(d if isinstance(d, dict) else {})
    return rows


def _highwater_digest(body: dict) -> str:
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _read_highwater(path: Path) -> dict | None:
    """Parse the high-water record; ``None`` when it is malformed."""
    try:
        record = json.loads(atomic_read_text(path))
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict):
        return None
    body = record.get("body")
    if not isinstance(body, dict) or body.get("kind") != "anchor_highwater":
        return None
    rows = body.get("ledger_rows")
    if not isinstance(rows, int) or isinstance(rows, bool) or rows < 1:
        return None
    if not isinstance(body.get("ledger_tip"), str) or not isinstance(
        body.get("latest_day"), str
    ):
        return None
    if not isinstance(record.get("key_id"), str) or not isinstance(
        record.get("signature"), str
    ):
        return None
    return record


def _ledger_extends_highwater(rows: list[dict], record: dict | None) -> bool:
    """Whether the ledger still holds the row the high-water record names."""
    if record is None:
        return False
    expected = record["body"]["ledger_rows"]
    return (
        len(rows) >= expected
        and str(rows[expected - 1].get("hash") or "") == record["body"]["ledger_tip"]
    )


def _write_anchor_highwater(audit_dir: Path) -> None:
    """Sign and publish the ledger's current row count, tip and latest day.

    Best effort: the anchor row is already durable, and the next anchor
    rewrites the record. The record never moves backwards, so a ledger that
    was cut short keeps failing verification after later anchors.
    """
    anchor_path = audit_dir / ANCHOR_FILENAME
    hw_path = audit_dir / ANCHOR_HIGHWATER_FILENAME
    try:
        with cross_process_lock(hw_path):
            rows = _ledger_rows(anchor_path)
            if not rows:
                return
            if not _HASH_RE.fullmatch(str(rows[-1].get("hash") or "")):
                # This lock does not exclude a concurrent ledger append, so the
                # last line may be half-written. Recording it would pin an empty
                # tip that later reads can never match; the next anchor retries.
                return
            if hw_path.exists() and not _ledger_extends_highwater(
                rows, _read_highwater(hw_path)
            ):
                log.warning(
                    "audit anchors: %s does not extend its signed high-water "
                    "record; leaving the record in place",
                    ANCHOR_FILENAME,
                )
                return
            days = [str(r["day"]) for r in rows if r.get("kind") == "anchor" and r.get("day")]
            body = {
                "kind": "anchor_highwater",
                "ledger_rows": len(rows),
                "ledger_tip": str(rows[-1].get("hash") or ""),
                "latest_day": max(days, default=""),
            }
            signed = sign_detached_digest(_highwater_digest(body))
            record = {"body": body, "key_id": signed["key_id"], "signature": signed["signature"]}
            atomic_write_text(hw_path, json.dumps(record, sort_keys=True) + "\n", mode=0o600)
            atomic_write_text(_anchor_marker_path(audit_dir), _HIGHWATER_MARKER_TEXT, mode=0o600)
    # failure-policy: best_effort
    except Exception as e:  # noqa: BLE001 - the anchor row itself is already durable
        log.warning("audit anchors: failed to write the high-water record: %s", e)


def _highwater_required(audit_dir: Path) -> bool:
    try:
        return atomic_read_text(_anchor_marker_path(audit_dir)) == _HIGHWATER_MARKER_TEXT
    except OSError:
        return False


def _verify_anchor_highwater(
    audit_dir: Path, rows: list[dict], pubkey_hex: str | None
) -> list[ChainBreak]:
    """Compare the ledger with its signed high-water record.

    Detects a ledger cut back to fewer rows (or rewritten below the recorded
    tip), which the per-day checks cannot see because they only cover days
    that still have an anchor row. An attacker holding the signing key can
    sign a new record; one without it cannot. Deleting the record together
    with ``.anchors.required`` is not detectable from local state alone.
    """
    hw_path = audit_dir / ANCHOR_HIGHWATER_FILENAME
    if not hw_path.exists():
        if _highwater_required(audit_dir):
            return [ChainBreak(
                0, "anchor_highwater_missing",
                f"{ANCHOR_HIGHWATER_FILENAME} is missing but was previously written")]
        return []
    record = _read_highwater(hw_path)
    if record is None:
        return [ChainBreak(
            0, "anchor_highwater_invalid", f"{ANCHOR_HIGHWATER_FILENAME} is malformed")]
    body = record["body"]
    public = pubkey_hex
    if public is None:
        public = trusted_audit_public_keys().get(record["key_id"])
    if not public or not verify_detached_digest(
        public, _highwater_digest(body), record["signature"]
    ):
        return [ChainBreak(
            0, "anchor_highwater_invalid",
            f"{ANCHOR_HIGHWATER_FILENAME} signature does not verify")]
    if not _ledger_extends_highwater(rows, record):
        return [ChainBreak(
            0, "anchor_ledger_truncated",
            f"{ANCHOR_FILENAME} has {len(rows)} rows and does not contain the "
            f"{body['ledger_rows']}-row ledger the signed high-water record covers "
            f"(latest anchored day {body['latest_day'] or 'none'})")]
    return []


def _today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


#: Exact key set of a ``retention_purge`` row in the anchor ledger, excluding
#: the chain fields every signed row carries.
_PURGE_BODY_KEYS = {"kind", "days", "cutoff_day", "ts"}


def record_retention_purge(audit_dir: Path, purged: list[dict]) -> bool:
    """Record in the ANCHOR LEDGER that policy retention removed day-files.

    Without this, a legitimate ``[retention] audit_days`` purge is
    indistinguishable from an attacker deleting a day-file: ``verify_anchors``
    reports ``anchored_file_deleted`` for every purged day, forever, because the
    anchor for that day stays in the append-only ledger while the file it
    describes is gone. That trains operators to ignore the one check that would
    show real tampering.

    The marker lands in ``anchors.ndjson`` rather than in a day-file for one
    reason that matters: retention itself never deletes the ledger (it prunes
    only ``YYYY-MM-DD.ndjson``), so the record outlives the next purge. A marker
    written into a live day-file is itself purged ~30 days later and the
    excusal evaporates -- the break comes back with no surviving explanation.

    Each entry commits to the exact ``tip_hash``/``row_count`` destroyed, so the
    row is not a blanket permission slip: :func:`verify_anchors` honours it only
    when it matches that day's latest anchor. A file mutated after its last
    anchor and *then* purged still fails, and an archived copy can be
    reconciled byte-for-byte against what the purge claims it removed.
    """
    if not _have_crypto() or not purged:
        return False
    anchor_path = audit_dir / ANCHOR_FILENAME
    if not anchor_path.exists():
        # No ledger means no anchors, so no day can be reported as deleted.
        return False
    signer = AuditSigner(anchor_path)
    ok = bool(signer.write({
        "kind": "retention_purge",
        "days": purged,
        "cutoff_day": max((str(p.get("day", "")) for p in purged), default=""),
        "ts": datetime.now(timezone.utc).isoformat(),
    }))
    if ok:
        _mark_anchor_ledger_required(audit_dir)
        _write_anchor_highwater(audit_dir)
    return ok


def retention_purged_days(audit_dir: Path) -> list[dict]:
    """Days that a signed ``retention_purge`` row accounts for, oldest first.

    :func:`verify_anchors` stops reporting these as deletions, so something has
    to say they happened -- otherwise "0 breaks" reads as "nothing was removed"
    when the truth is "two days were removed and here is the signed record of
    it". Silence would make the check less informative than the bug it fixed.
    """
    anchor_path = audit_dir / ANCHOR_FILENAME
    if not anchor_path.exists():
        return []
    out: dict[str, dict] = {}
    try:
        with open(anchor_path, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(d, dict) or d.get("kind") != "retention_purge":
                    continue
                for entry in d.get("days") or []:
                    if isinstance(entry, dict) and isinstance(entry.get("day"), str):
                        out[entry["day"]] = entry
    except OSError:  # pragma: no cover - reported by verify_anchors instead
        return []
    return [out[k] for k in sorted(out)]


def _purge_authorizes(entry: object, anchor: dict) -> bool:
    """Whether a purge entry accounts for exactly the anchored content.

    Fail closed on anything partial: an entry that cannot name the tip it
    destroyed is not evidence that the deletion was the policy-driven one.
    """
    if not isinstance(entry, dict):
        return False
    tip = entry.get("tip_hash")
    count = entry.get("row_count")
    if not isinstance(tip, str) or not _SHA256_RE.fullmatch(tip):
        return False
    if not isinstance(count, int) or isinstance(count, bool):
        return False
    return tip == anchor.get("tip_hash") and count == anchor.get("row_count")


def ensure_anchors(audit_dir: Path) -> int:
    """Record a tip-ledger anchor for every COMPLETED day-file lacking one.

    Only completed days (< today, UTC) are anchored -- today's file is still
    growing. Already-anchored days are left alone: we never silently re-anchor
    over a tampered file (that's ``verify_anchors``' job to flag); a legitimate
    GDPR erase re-anchors its day explicitly via ``reanchor_day_after_erase``.
    Returns the number of anchors written.
    """
    if not _have_crypto():
        return 0
    if not _ensure_anchor_ledger(audit_dir):
        log.warning(
            "audit anchors: %s is missing but was previously required; refusing to rebuild",
            ANCHOR_FILENAME,
        )
        return 0
    today = _today_utc()
    anchored = _anchored_days(audit_dir)
    written = 0
    for day_file in day_files(audit_dir):
        day = day_file.stem
        if day >= today or day in anchored:
            continue
        with cross_process_lock(day_file):
            # A writer may have selected this day before midnight. Hold its
            # append lock boundary from tip discovery through anchor publication.
            with cross_process_lock(audit_dir / ANCHOR_FILENAME):
                if day in _anchored_days(audit_dir):
                    continue
            try:
                tip, count = _file_tip_and_count(day_file)
            # failure-policy: fail_soft_with_audit
            except Exception as e:
                log.warning("audit anchors: cannot read %s; not anchored: %s", day_file.name, e)
                continue
            if count and not tip:
                log.warning("audit anchors: %s has no signed rows; not anchored", day_file.name)
                continue
            if count and _append_anchor(audit_dir, day, tip, count):
                written += 1
    return written


def reanchor_day_after_erase(audit_dir: Path, day_file: Path) -> None:
    """After a GDPR erase rewrites a completed day-file (changing its tip),
    append a fresh superseding anchor so ``verify_anchors`` matches the new
    state. The prior anchor stays in the append-only ledger -- an auditable
    record that the day was modified."""
    if not _have_crypto():
        return
    day = day_file.stem
    if not _DAY_RE.fullmatch(day) or day >= _today_utc():
        return  # not a completed day-file
    tip, count = _file_tip_and_count(day_file)
    if count and tip:
        _append_anchor(audit_dir, day, tip, count)


def verify_anchors(audit_dir: Path, pubkey_hex: str | None = None) -> list[ChainBreak]:
    """Cross-file tamper-evidence: confirm every anchored day-file still exists
    and matches its latest recorded tip hash + row count. Catches deletion or
    truncation of a whole day-file, which per-file ``verify_chain`` cannot.

    Verifies the anchor ledger's own signed chain first, then each day.
    Empty list = intact.
    """
    anchor_path = audit_dir / ANCHOR_FILENAME
    if not anchor_path.exists():
        has_completed_days = any(p.stem < _today_utc() for p in day_files(audit_dir))
        if has_completed_days or _anchor_marker_path(audit_dir).exists():
            return [
                ChainBreak(
                    0,
                    "anchor_ledger_missing",
                    f"{ANCHOR_FILENAME} is missing; "
                    "cross-file audit tamper-evidence cannot be verified",
                )
            ]
        return []
    breaks = list(verify_chain(anchor_path, pubkey_hex))
    breaks.extend(_verify_anchor_highwater(audit_dir, _ledger_rows(anchor_path), pubkey_hex))
    # A purge row only excuses a deletion when the ledger's own signed chain is
    # intact. Otherwise an attacker who can append unsigned lines could write
    # their own permission slip for the day-file they just deleted.
    ledger_intact = not breaks
    # The ledger is append-only; the last anchor for a day wins (supersession).
    latest: dict[str, dict] = {}
    anchored_at: dict[str, int] = {}
    purged: dict[str, dict] = {}
    purged_at: dict[str, int] = {}
    with open(anchor_path, encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if not line.strip():
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(d, dict):
                continue
            if d.get("kind") == "anchor" and d.get("day"):
                latest[str(d["day"])] = d
                anchored_at[str(d["day"])] = idx
            elif d.get("kind") == "retention_purge":
                for entry in d.get("days") or []:
                    if isinstance(entry, dict) and isinstance(entry.get("day"), str):
                        purged[entry["day"]] = entry
                        purged_at[entry["day"]] = idx
    for day, anc in sorted(latest.items()):
        day_file = audit_dir / f"{day}.ndjson"
        if not day_file.exists():
            # Retention legitimately deletes day-files older than [retention]
            # audit_days. That is policy, not tampering -- but only when it is
            # recorded in this signed ledger, commits to the exact tip that was
            # destroyed, and was recorded AFTER the anchor it retires (an
            # append-only ledger cannot pre-authorize a future deletion).
            if (
                ledger_intact
                and day in purged
                and purged_at[day] > anchored_at.get(day, -1)
                and _purge_authorizes(purged[day], anc)
            ):
                continue
            breaks.append(ChainBreak(
                0, "anchored_file_deleted", f"{day}.ndjson is anchored but missing"))
            continue
        try:
            tip, count = _file_tip_and_count(day_file)
        # failure-policy: fail_closed
        except Exception as e:
            breaks.append(ChainBreak(
                0, "unreadable_segment", f"{day}: {e}"))
            continue
        if tip != anc.get("tip_hash"):
            breaks.append(ChainBreak(
                0, "anchor_tip_mismatch",
                f"{day}: tip {tip[:12]}... != anchored {str(anc.get('tip_hash'))[:12]}..."))
        if count != anc.get("row_count"):
            breaks.append(ChainBreak(
                0, "anchor_count_mismatch",
                f"{day}: {count} rows != anchored {anc.get('row_count')}"))
    return breaks


def reanchor_file(path: Path, *, force: bool = False, preverified: bool = False) -> int:
    """Re-chain + re-sign every row of a signed audit file, in place.

    A GDPR erase tombstones or removes rows but does NOT recompute the
    ``prev_hash``/``hash``/``sig`` chain, so ``verify_chain()`` then reports
    breaks that are indistinguishable from tampering. This rewrites the file,
    recomputing each row's chain fields under the current key so the chain
    verifies clean again, preserving row content and order. The caller also
    records a signed ``erase`` marker (the CLI writes it after the scrub) so a
    verifier holding the trusted pubkey can see the cut was authorized.

    By default, re-anchoring first verifies the existing file and refuses to
    rewrite a broken chain. Callers that just performed an authorized erase
    may pass ``preverified=True`` only after verifying the original file before
    mutating it; this prevents a routine erase from laundering older tampering.

    ``force`` re-signs even rows that currently carry no signature (e.g. a
    file whose every signed row was tombstoned by the erase). Without it, a
    file with no signed rows is left untouched (returns -1) -- erasing an
    unsigned log has no chain to repair.

    Returns rows re-signed, 0 if no rewrite was needed (already consistent),
    or -1 if skipped (crypto unavailable, missing file, or unsigned without
    ``force``).

    Re-anchoring re-signs under the host key: it makes *authorized* erasure
    verifiable-clean. It is not extra protection against an attacker who
    already holds that key -- that is inherent to same-host key storage.
    """
    if not _have_crypto():
        return -1
    if not path.exists() or path.is_dir():
        return -1
    # Re-chaining is a whole-file read-modify-write. Take the same lock
    # AuditSigner.write holds, or a concurrent append lands on the pre-rewrite
    # inode and is discarded by the atomic replace below. Reentrant, so the
    # erase path (which already holds it across read+write+reanchor) nests.
    with cross_process_lock(path):
        return _reanchor_file_locked(path, force=force, preverified=preverified)


def _reanchor_file_locked(
    path: Path, *, force: bool = False, preverified: bool = False
) -> int:
    """``reanchor_file`` body, with the file's rewrite lock already held."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    try:
        ensure_private_directory(path.parent)
        ensure_private_file(path, 0o600)
        raw = atomic_read_bytes(path)
    except OSError:
        return -1
    # A closed day-file may be at-rest *sealed*. Re-chain its decrypted
    # NDJSON, but remember the sealed state so the rewrite below writes it back
    # sealed -- a re-anchor (e.g. after a GDPR erase) must not silently unseal a
    # confidential segment to plaintext.
    from ..crypto_at_rest import is_sealed
    was_sealed = is_sealed(raw)
    original = _segment_text(path)

    parsed: list[tuple[str, object]] = []
    any_signed = False
    for raw in original.splitlines():
        if not raw.strip():
            continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Never drop data on a rewrite: preserve unparseable lines
            # verbatim (and out of the chain), mirroring verify_chain.
            parsed.append(("raw", raw))
            continue
        if not isinstance(data, dict):
            parsed.append(("raw", raw))
            continue
        if data.get("sig") and data.get("hash") and data.get("key_id"):
            any_signed = True
        parsed.append(("json", data))

    if not any_signed and not force:
        return -1
    if not preverified:
        breaks = verify_chain(path)
        if breaks:
            log.warning(
                "audit reanchor: refusing to rewrite %s; chain is not clean (%s)",
                path,
                breaks[0],
            )
            return -1

    priv_bytes, _pub, key_id = _load_or_create_keypair()
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

    out_lines: list[str] = []
    prev = ""
    resigned = 0
    for kind, val in parsed:
        if kind == "raw":
            out_lines.append(val)  # type: ignore[arg-type]
            continue
        assert isinstance(val, dict)
        # Strip the old chain fields, then rebuild them exactly as
        # AuditSigner.write does (hash over payload incl. prev_hash + key_id,
        # sort_keys=True; sig over the hash bytes).
        payload = {k: v for k, v in val.items() if k not in ("hash", "sig", "prev_hash", "key_id")}
        payload["prev_hash"] = prev
        payload["key_id"] = key_id
        row_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        payload["hash"] = row_hash
        payload["sig"] = signer.sign(bytes.fromhex(row_hash)).hex()
        out_lines.append(json.dumps(payload, default=str))
        prev = row_hash
        resigned += 1

    new_content = "".join(line + "\n" for line in out_lines)
    if new_content == original:
        return 0  # untouched rows under an unchanged key -> no rewrite

    from .sealing import encode_segment
    new_bytes = encode_segment(new_content, sealed=was_sealed)

    try:
        atomic_write_bytes(path, new_bytes, mode=0o600)
    except OSError as e:
        log.warning("audit reanchor: %s: %s", path, e)
        return -1
    return resigned


__all__ = [
    "AuditSigner",
    "sign_detached_digest",
    "verify_detached_digest",
    "trusted_audit_public_keys",
    "verify_chain",
    "verify_ed25519",
    "ChainBreak",
    "KEY_DIR",
    "active_key_is_offhost",
    "reanchor_file",
    "record_retention_purge",
    "rotate_audit_keypair",
]
