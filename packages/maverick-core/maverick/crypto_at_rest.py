"""AES-256-GCM encryption at rest for Lightwork's sensitive local stores.

The kernel keeps its state in plaintext on disk by default (the world model, the
audit log, and the cross-session memory directory). That is fine for a personal
agent but is a GDPR Art. 32 / HIPAA exposure the moment the agent handles
sensitive data: anyone who can read ``~/.maverick`` sees everything.

This module provides authenticated at-rest encryption for bytes/text plus key
management that reuses the local-keyfile pattern of the audit signer. It is
**on by default** (secure-by-default): new writes are sealed and the key
auto-generates on first use. Disable it with ``[encryption] at_rest = false`` /
``MAVERICK_ENCRYPT_AT_REST=0`` (or the whole posture via ``[security]
secure_defaults = false`` / ``MAVERICK_SECURE_DEFAULT=0``); it is also **implied
by enterprise mode** and **forced by a compliance floor** (e.g. HIPAA), which an
opt-out cannot override. Existing installs are safe to leave on -- reads are
plaintext-tolerant, so rows written before it was enabled are returned unchanged
until rewritten (``maverick encryption migrate`` seals them eagerly).

Key resolution (first match wins):
  1. ``MAVERICK_ENCRYPTION_KEY`` — a 32-byte key as hex or base64, so an operator
     can inject a KMS-derived key without it ever touching disk.
  2. ``~/.maverick/keys/at_rest.key`` — generated on first use, ``chmod 600``.

Every Postgres governed authority additionally requires the injected key plus
``MAVERICK_ENCRYPTION_KEY_DIGEST=sha256:<full digest>``—including an explicitly
selected single-replica deployment. The digest is verified from decoded key
bytes before shared I/O; node-local rotation-keyring files are refused.

Sealed blobs carry a magic header (:data:`_MAGIC`), so :func:`unseal` transparently
returns plaintext written *before* encryption was enabled — a gradual migration
with no flag-day re-encrypt.

Coverage (what is actually sealed today):
  - the cross-session **memory** store (files), and
  - the **world-DB content columns** sealed via ``encryption_migrate._SEALED_COLUMNS``
    — facts (+ fact history values), conversation turns/messages, open
    questions, goal content (titles/descriptions/results) + per-agent goal
    events, episode summaries/outcomes, parked-approval action/scope/detail,
    artifact content, project names/descriptions, and sign-off notes.
  The audit log's **closed day-files** can be sealed via ``maverick audit seal``
  (``audit/sealing.py``); the *current* day-file stays plaintext for the live
  append + signing path, and reads/``audit verify`` decrypt sealed segments
  transparently. The log is independently *signed* for tamper-evidence
  (``audit/signing.py``) -- integrity, orthogonal to this confidentiality.

By default a sealed column read back unsealed (legacy/pre-migration) is passed
through; :func:`strict_at_rest` makes that an integrity failure instead.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from . import file_lock
from .paths import data_dir

log = logging.getLogger(__name__)

_MAGIC = b"MVKAR1\n"          # versioned header: Lightwork At-Rest v1 (single key)
_MAGIC_V2 = b"MVKAR2\n"       # v2: keyring header -- MAGIC || keyid(8) || nonce || ct
# Per-tenant envelope-sealed blob header. MUST equal tenant_kms._SEAL_MAGIC (a
# test asserts this); duplicated here so is_sealed() stays cheap and we avoid a
# crypto_at_rest <-> tenant_kms import cycle (tenant_kms imports from this module).
_TENANT_MAGIC = b"MVKTEN1\n"
_STREAM_MAGIC = b"MVKASF1\n"  # bounded authenticated audit frames
_NONCE_BYTES = 12
_KEY_BYTES = 32              # AES-256
_KEYID_BYTES = 8             # short key fingerprint embedded in v2 blobs
# On-disk key location. ``_KEY_PATH`` is an OVERRIDE (tests pin it to a tmp
# dir; an operator could too); ``None`` -- the production default -- means
# "resolve <home>/keys/at_rest.key for the DEPLOYMENT when asked" via
# :func:`_key_path`. Evaluating ``_KEY_PATH = data_dir(...)`` at import would
# run ``data_dir()`` DURING import: it resolves the tenant
# through the client binding, which loads config, which -- when the dashboard
# overlay holds a sealed value -- imports THIS module to open it. With the
# import still in progress that raises "cannot import name
# 'deployment_key_scope' from partially initialized module" on the very first
# ``data_dir()`` call of a fresh process, and every production task exits
# before it can listen. Nothing may touch the data directory at import time
# here.
#
# The key is one per deployment, not one per request tenant. The old
# import-time binding always landed before any request scope existed, so every
# row -- tenant-scoped or shared -- has been sealed under the deployment key
# (MAVERICK_TENANT / the client binding decide its directory); per-tenant
# separation is the KEK derivation on top of it. Resolving the path from the
# request-scoped tenant instead would mint a fresh key per workspace and leave
# a row sealed inside a tenant-bound request unreadable to any reader outside
# that scope (the owner-invite flow proved it), so the request context is
# deliberately ignored here.
_KEY_PATH: Path | None = None


def _deployment_tenant() -> str | None:
    """The tenant the deployment itself is bound to (``MAVERICK_TENANT`` or the
    client binding), ignoring any request-scoped ``set_tenant`` context."""
    env = os.environ.get("MAVERICK_TENANT", "").strip()
    if env:
        return env
    from .client import strict_client_id

    return strict_client_id()


def _key_path() -> Path:
    """The deployment's at-rest key file, resolved when asked (never at import)."""
    if _KEY_PATH is not None:
        return _KEY_PATH
    return data_dir("keys", "at_rest.key", tenant=_deployment_tenant())
_KEY_ENV = "MAVERICK_ENCRYPTION_KEY"
_KEY_DIGEST_ENV = "MAVERICK_ENCRYPTION_KEY_DIGEST"
_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")

# Shared governed records cannot depend on node-local tenant DEKs. They opt into
# the deployment at-rest key while performing Postgres I/O. Context-local state
# keeps concurrent tenant requests isolated and prevents a process-wide change
# to ordinary tenant-scoped seals.
_FORCE_DEPLOYMENT_KEY = ContextVar(
    "maverick_force_deployment_at_rest_key",
    default=False,
)
_FORCE_EXTERNAL_FLEET_KEY = ContextVar(
    "maverick_force_external_fleet_at_rest_key",
    default=False,
)
_SHARED_KEY_IDENTITY_LOCK = threading.Lock()
_SHARED_KEY_IDENTITY_DIGEST: str | None = None
_SHARED_KEY_BYTES: bytes | None = None


@contextmanager
def deployment_key_scope():
    """Use the deployment at-rest key for shared authority I/O only.

    This is not a general encryption-mode switch. Callers keep the scope around
    only the governed-record operation whose ciphertext must be decryptable by
    every replica using the externally pinned fleet key.
    """
    token = _FORCE_DEPLOYMENT_KEY.set(True)
    try:
        yield
    finally:
        _FORCE_DEPLOYMENT_KEY.reset(token)


@contextmanager
def external_fleet_key_scope():
    """Use only the admitted external key for process-wide shared seals.

    Tenant envelope encryption remains tenant-scoped. This closes the
    verification/use race in which a node-local rotation key could appear
    after the fleet key was checked but before a shared record was sealed.
    """
    token = _FORCE_EXTERNAL_FLEET_KEY.set(True)
    try:
        yield
    finally:
        _FORCE_EXTERNAL_FLEET_KEY.reset(token)


class EncryptionUnavailable(RuntimeError):
    """At-rest encryption was requested but cannot be performed (missing crypto
    or an unreadable/invalid key). Callers fail closed rather than write plaintext."""


def _have_crypto() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        return True
    except ImportError:
        return False


def _truthy(value: object) -> bool:
    """True for the canonical affirmative tokens, aligned with
    ``maverick.security_defaults._TRUE`` so an operator's natural ``on`` / ``yes``
    / ``enabled`` / ``y`` reads the same here as in the rest of the security
    stack. A divergent, smaller set silently mis-read ``enabled`` as False and --
    for the at-rest floor -- disabled encryption, storing plaintext."""
    try:
        from .security_defaults import _TRUE
    except Exception:  # pragma: no cover -- security_defaults always importable
        _TRUE = {"1", "true", "yes", "on", "enable", "enabled", "y", "t"}
    return str(value).strip().lower() in _TRUE


def _falsey(value: object) -> bool:
    """True for the canonical negative tokens (``0``/``false``/``off``/
    ``disabled``/...). Used by the at-rest security floor, which stays ON unless
    an EXPLICIT false token is given -- an unrecognised value must not silently
    downgrade to plaintext."""
    try:
        from .security_defaults import _FALSE
    except Exception:  # pragma: no cover
        _FALSE = {"0", "false", "no", "off", "disable", "disabled", "n", "f"}
    return str(value).strip().lower() in _FALSE


def at_rest_enabled() -> bool:
    """On by default (secure-by-default), overridable per deployment.

    Compliance floors are mandatory and strictest-wins: HIPAA-mode at-rest
    encryption cannot be disabled by leaving or setting the standalone
    encryption knob false. With no such floor, ``MAVERICK_ENCRYPT_AT_REST`` env
    wins over ``[encryption] at_rest`` in config, which wins over enterprise
    mode, which falls back to
    :func:`maverick.security_defaults.secure_by_default` -- ON unless explicitly
    disabled (``MAVERICK_ENCRYPT_AT_REST=0`` / ``[encryption] at_rest = false``,
    or the whole hardened cluster via ``MAVERICK_SECURE_DEFAULT=0``).
    """
    try:
        from .compliance_profiles import FLOOR_ENCRYPTION_AT_REST, requires_floor
        if requires_floor(FLOOR_ENCRYPTION_AT_REST):
            return True
    except Exception:
        pass
    env = os.environ.get("MAVERICK_ENCRYPT_AT_REST")
    if env is not None and env.strip() != "":
        # Security floor: ON unless an EXPLICIT false token is given. An
        # unrecognised value keeps encryption on (fail-safe) rather than
        # silently writing plaintext.
        return not _falsey(env)
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("encryption") or {}
    except Exception:
        cfg = {}
    if "at_rest" in cfg:
        v = cfg.get("at_rest")
        if isinstance(v, str):
            return not _falsey(v)
        return bool(v)
    # Enterprise mode implies at-rest encryption (sensitive data stays sealed).
    # Secure-by-default otherwise: seal new writes unless explicitly disabled.
    # Safe for existing installs -- reads are plaintext-tolerant (unseal_from_str
    # returns unmarked legacy values unchanged), so mixing sealed + plaintext
    # rows just works; the key auto-generates on first use (~/.maverick/keys).
    try:
        from .enterprise import enterprise_enabled
        if enterprise_enabled():
            return True
        from .security_defaults import secure_by_default
        return secure_by_default()
    except Exception:
        return False


def _deployment_compliance_encryption_floor(
    config: Mapping[str, object],
    *,
    source_errors: object,
) -> tuple[bool, bool]:
    """Return ``(policy_valid, floor_required)`` from one global snapshot."""
    try:
        from .compliance_profiles import (
            FLOOR_ENCRYPTION_AT_REST,
            required_floors,
            resolve_profiles,
        )

        profiles = resolve_profiles(config, source_errors=source_errors)
        return True, FLOOR_ENCRYPTION_AT_REST in required_floors(profiles)
    except Exception:
        return False, False


def _deployment_secure_defaults_enabled(
    config: Mapping[str, object],
) -> bool | None:
    """Resolve the umbrella secure-default setting; ``None`` means invalid."""
    secure_env = os.environ.get("MAVERICK_SECURE_DEFAULT")
    if secure_env is not None and secure_env.strip() != "":
        normalized = secure_env.strip().lower()
        if normalized in {
            "1", "true", "yes", "on", "enable", "enabled", "y", "t",
        }:
            return True
        if normalized in {
            "0", "false", "no", "off", "disable", "disabled", "n", "f",
        }:
            return False
        # Runtime ignores an unrecognized umbrella value and reads config.
    security = config.get("security")
    if security is None:
        return True
    if not isinstance(security, Mapping):
        return None
    value = security.get("secure_defaults")
    if value is None:
        return True
    if isinstance(value, str):
        return not _falsey(value)
    return value if isinstance(value, bool) else None


def deployment_at_rest_enabled(
    *,
    config: object | None = None,
    source_errors: object | None = None,
) -> bool:
    """Resolve the deployment-global at-rest floor without tenant overlays.

    Shared-authority admission cannot use :func:`at_rest_enabled` because that
    compatibility resolver intentionally reads the active tenant overlay and
    fails soft. This resolver evaluates one trusted global snapshot, mirrors
    the runtime precedence, and returns ``False`` on malformed or unreadable
    policy so a key digest alone cannot manufacture a green readiness result.
    """
    if config is None or source_errors is None:
        try:
            from .config import config_source_errors, load_global_config

            if config is None:
                config = load_global_config()
            if source_errors is None:
                source_errors = config_source_errors(include_tenant=False)
        except Exception:
            return False
    if source_errors or not isinstance(config, Mapping):
        return False

    compliance_valid, compliance_floor = (
        _deployment_compliance_encryption_floor(
            config,
            source_errors=source_errors,
        )
    )
    if not compliance_valid:
        return False
    if compliance_floor:
        return True

    env = os.environ.get("MAVERICK_ENCRYPT_AT_REST")
    if env is not None and env.strip() != "":
        return not _falsey(env)
    encryption = config.get("encryption")
    if encryption is not None:
        if not isinstance(encryption, Mapping):
            return False
        if "at_rest" in encryption:
            value = encryption.get("at_rest")
            if isinstance(value, str):
                return not _falsey(value)
            if not isinstance(value, bool):
                return False
            return value

    try:
        from .enterprise import deployment_enterprise_enabled

        if deployment_enterprise_enabled(config=config, source_errors=()):
            return True
    except Exception:
        return False

    return _deployment_secure_defaults_enabled(config) is True


def per_tenant_at_rest() -> bool:
    """Per-tenant envelope encryption (default: on in enterprise mode, else off).

    When on **and** at-rest is enabled, new seals use the *current tenant's* own
    data key (:mod:`maverick.tenant.kms`) instead of the single process-wide key,
    so one tenant's key never opens another tenant's data — the posture a hosted
    multi-tenant store needs. Reads auto-detect by magic header, so data already
    sealed with the global key stays readable (transparent migration, no flag-day
    re-encrypt). ``MAVERICK_ENCRYPT_PER_TENANT`` env wins over ``[encryption]
    per_tenant``.

    Intended for deployments where every read/write is tenant-scoped (the seal
    is bound to ``paths.current_tenant()``); on a single-tenant box leave it off."""
    env = os.environ.get("MAVERICK_ENCRYPT_PER_TENANT")
    if env is not None and env.strip() != "":
        return _truthy(env)
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("encryption") or {}
    except Exception:
        return False
    v = cfg.get("per_tenant")
    return _truthy(v) if isinstance(v, str) else bool(v)


def strict_at_rest() -> bool:
    """Opt-in strict read mode (default off). When on -- and at-rest is enabled --
    a value read back from a *sealed column* that is NOT sealed is treated as an
    integrity failure (withheld) instead of trusted as plaintext.

    Enable it only AFTER ``maverick encryption migrate`` has sealed legacy rows:
    before migration, pre-existing plaintext in those columns is expected, and
    strict mode would (correctly) withhold it. ``MAVERICK_ENCRYPT_STRICT`` env wins
    over ``[encryption] strict``."""
    env = os.environ.get("MAVERICK_ENCRYPT_STRICT")
    if env is not None and env.strip() != "":
        return _truthy(env)
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("encryption") or {}
    except Exception:
        return False
    v = cfg.get("strict")
    return _truthy(v) if isinstance(v, str) else bool(v)


def _decode_injected_key(raw: str) -> bytes:
    raw = raw.strip()
    if len(raw) == _KEY_BYTES * 2:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    try:
        return base64.b64decode(raw, validate=True)
    except Exception as e:  # noqa: BLE001
        raise EncryptionUnavailable(
            "MAVERICK_ENCRYPTION_KEY is not valid hex or base64"
        ) from e


def shared_authority_key_identity_required() -> bool:
    """Whether this deployment needs one externally proven fleet key.

    Every Postgres governed authority shares encrypted rows, including an
    explicitly selected single-replica deployment. Allowing a node to generate
    ``at_rest.key`` or a local rotation keyring in that posture makes the
    persistence plane shared but decryptability node-local. Configuration
    uncertainty is security-significant and therefore returns ``True``.
    """
    raw_replicas = str(os.environ.get("MAVERICK_REPLICA_COUNT") or "1").strip()
    try:
        replicas = int(raw_replicas)
    except (TypeError, ValueError, OverflowError):
        return True
    if replicas < 1 or raw_replicas != str(replicas):
        return True
    if replicas > 1:
        return True
    try:
        from .config import (
            governed_records_config_source_errors,
            load_governed_records_config,
        )
        from .enterprise import deployment_enterprise_enabled

        config = load_governed_records_config()
        errors = governed_records_config_source_errors()
        if errors or not isinstance(config, dict):
            return True
        governed = config.get("governed_records") or {}
        world = config.get("world_model") or {}
        if not isinstance(governed, dict) or not isinstance(world, dict):
            return True
        configured = (
            os.environ.get("MAVERICK_GOVERNED_RECORDS_BACKEND")
            or governed.get("backend")
            or "auto"
        )
        backend = str(configured).strip().lower()
        if backend not in {"auto", "local", "postgres"}:
            return True
        world_backend = str(
            os.environ.get("MAVERICK_WORLD_BACKEND")
            or world.get("backend")
            or "sqlite"
        ).strip().lower()
        # Postgres is shared process authority even for an explicitly declared
        # single replica. Its encrypted rows must never depend on a node-local
        # rotation keyring that another process cannot resolve.
        if backend == "postgres" or (
            backend != "local" and world_backend == "postgres"
        ):
            return True
        return deployment_enterprise_enabled(
            config=config,
            source_errors=errors,
        )
    except Exception:
        return True


def require_shared_deployment_key_identity() -> str:
    """Verify the externally injected fleet encryption-key identity.

    Returns the canonical full SHA-256 digest after verification.  The digest
    is an operator-supplied trust anchor, not a digest learned from whichever
    key a node happened to load.  Local rotation-keyring files are refused:
    they are node-local and the current file format has no deployment-global
    keyring authority or externally pinned ring manifest.
    """
    if not deployment_at_rest_enabled():
        raise EncryptionUnavailable(
            "shared authority application at-rest encryption is disabled or unverified"
        )
    raw = os.environ.get(_KEY_ENV)
    if raw is None or not raw.strip():
        raise EncryptionUnavailable(
            "shared authority encryption requires an externally injected key"
        )
    key = _decode_injected_key(raw)
    if len(key) != _KEY_BYTES:
        raise EncryptionUnavailable(
            f"{_KEY_ENV} must decode to {_KEY_BYTES} bytes, got {len(key)}"
        )

    expected = str(os.environ.get(_KEY_DIGEST_ENV) or "").strip()
    if not _SHA256_DIGEST.fullmatch(expected):
        raise EncryptionUnavailable(
            "shared authority encryption requires a canonical external key digest"
        )
    actual = "sha256:" + hashlib.sha256(key).hexdigest()
    if not hmac.compare_digest(expected, actual):
        raise EncryptionUnavailable(
            "shared authority encryption key does not match its deployment digest"
        )

    ring = _keyring_dir()
    try:
        ring_keys = tuple(ring.glob("*.key")) if ring.exists() else ()
    except OSError as exc:
        raise EncryptionUnavailable(
            "shared authority encryption keyring cannot be inspected"
        ) from exc
    if ring_keys:
        raise EncryptionUnavailable(
            "shared authority encryption refuses node-local rotation keys"
        )
    global _SHARED_KEY_BYTES, _SHARED_KEY_IDENTITY_DIGEST
    with _SHARED_KEY_IDENTITY_LOCK:
        admitted = _SHARED_KEY_IDENTITY_DIGEST
        if admitted is None:
            _SHARED_KEY_IDENTITY_DIGEST = actual
            _SHARED_KEY_BYTES = bytes(key)
        elif not hmac.compare_digest(admitted, actual):
            raise EncryptionUnavailable(
                "shared authority encryption key identity changed after process admission"
            )
        elif _SHARED_KEY_BYTES is None or not hmac.compare_digest(
            _SHARED_KEY_BYTES,
            key,
        ):
            raise EncryptionUnavailable(
                "shared authority encryption key changed after process admission"
            )
    return actual


def _admitted_shared_key() -> bytes:
    """Return a detached copy of the process-pinned external fleet key."""
    with _SHARED_KEY_IDENTITY_LOCK:
        key = _SHARED_KEY_BYTES
    if key is None:
        require_shared_deployment_key_identity()
        with _SHARED_KEY_IDENTITY_LOCK:
            key = _SHARED_KEY_BYTES
    if key is None:  # pragma: no cover - verifier above either pins or raises
        raise EncryptionUnavailable(
            "shared authority encryption key identity is unavailable"
        )
    return bytes(key)


def _reset_shared_key_identity_for_testing() -> None:
    """Clear process admission state for isolated tests only."""
    global _SHARED_KEY_BYTES, _SHARED_KEY_IDENTITY_DIGEST
    with _SHARED_KEY_IDENTITY_LOCK:
        _SHARED_KEY_BYTES = None
        _SHARED_KEY_IDENTITY_DIGEST = None


def _secure_key_dir() -> None:
    """Ensure the on-disk key directory is private before touching key material."""
    try:
        file_lock.ensure_private_directory(_key_path().parent)
    except OSError as e:
        raise EncryptionUnavailable(
            f"cannot secure at-rest key directory {_key_path().parent}: {e}"
        ) from e


def _ensure_private_key_file() -> None:
    """Tighten existing key-file permissions before loading it."""
    try:
        file_lock.ensure_private_file(_key_path())
    except OSError as e:
        raise EncryptionUnavailable(f"cannot secure at-rest key {_key_path()}: {e}") from e


def _read_key_file() -> bytes:
    _secure_key_dir()
    _ensure_private_key_file()
    try:
        key = bytes.fromhex(file_lock.atomic_read_text(_key_path()).strip())
    except (OSError, ValueError) as e:
        raise EncryptionUnavailable(f"cannot read at-rest key {_key_path()}: {e}") from e
    if len(key) != _KEY_BYTES:
        raise EncryptionUnavailable(f"at-rest key {_key_path()} is malformed")
    return key


def _write_new_key_file(key: bytes) -> None:
    _secure_key_dir()
    try:
        file_lock.atomic_create_text(_key_path(), key.hex())
    except FileExistsError:
        raise
    except OSError as e:
        raise EncryptionUnavailable(f"cannot write at-rest key {_key_path()}: {e}") from e


def _load_or_create_key() -> bytes:
    raw = os.environ.get(_KEY_ENV)
    if raw:
        key = _decode_injected_key(raw)
        if len(key) != _KEY_BYTES:
            raise EncryptionUnavailable(
                f"MAVERICK_ENCRYPTION_KEY must decode to {_KEY_BYTES} bytes, got {len(key)}"
            )
        return key
    if _key_path().exists():
        return _read_key_file()
    # First use: generate + persist atomically with private directory/file modes.
    key = secrets.token_bytes(_KEY_BYTES)
    try:
        _write_new_key_file(key)
    except FileExistsError:
        # Another process won the first-use race; load the private key it wrote.
        return _read_key_file()
    # At-rest is on by default now, so this auto-generation happens silently on
    # most installs. The key file is the ONLY way to read sealed data -- losing it
    # loses everything sealed under it -- so make the durability requirement loud.
    log.warning(
        "at-rest encryption generated a new key at %s. This key is the only way "
        "to decrypt sealed data; if it is lost, that data is unrecoverable. Back "
        "it up now to a secure location: `maverick encryption backup-key --to "
        "<dir>` (or inject your own via MAVERICK_ENCRYPTION_KEY).",
        _key_path(),
    )
    return key


def _load_existing_key() -> bytes:
    """The deployment key for a READ. A read never generates key material: a
    missing key file means the key was lost, and minting a replacement would
    report that as a wrong key and seal later writes under the new one."""
    if not os.environ.get(_KEY_ENV) and not _key_path().exists():
        raise EncryptionUnavailable(
            f"the at-rest key {_key_path()} is missing; restore it from your "
            "key backup (or inject it via MAVERICK_ENCRYPTION_KEY) to read "
            "sealed data"
        )
    return _load_or_create_key()


def backup_key_material(dest_dir: Path) -> list[Path]:
    """Copy the at-rest key material to ``dest_dir`` for safe escrow.

    Copies the primary key (``at_rest.key``) and every rotation-keyring key
    (``at_rest.d/*.key``) into ``dest_dir``, each ``0600`` inside a ``0700``
    directory. Returns the paths written. Raises :class:`EncryptionUnavailable`
    when no key material exists yet (nothing has been sealed) or the copy fails.

    The copies are plaintext key material -- store them somewhere at least as
    protected as the originals (a secrets manager / offline vault), not next to
    the data they unlock. A key injected via ``MAVERICK_ENCRYPTION_KEY`` lives
    in your secrets manager already and is not on disk to copy.
    """
    sources: list[Path] = []
    if _key_path().exists():
        sources.append(_key_path())
    try:
        sources.extend(sorted(_keyring_dir().glob("*.key")))
    except OSError:
        pass
    if not sources:
        raise EncryptionUnavailable(
            f"no at-rest key material to back up under {_key_path().parent} "
            "(nothing has been sealed yet, or the key is injected via "
            "MAVERICK_ENCRYPTION_KEY and not stored on disk)."
        )
    try:
        file_lock.ensure_private_directory(dest_dir)
        dest_stat = dest_dir.lstat()
        if hasattr(os, "geteuid") and dest_stat.st_uid != os.geteuid():
            raise OSError("backup destination must be owned by the current user")
    except OSError as e:
        raise EncryptionUnavailable(
            f"cannot prepare key backup dir {dest_dir}: {e}"
        ) from e
    written: list[Path] = []
    for src in sources:
        dst = dest_dir / src.name
        try:
            file_lock.ensure_private_file(src)
            file_lock.atomic_create_bytes(dst, file_lock.atomic_read_bytes(src))
        except OSError as e:
            raise EncryptionUnavailable(
                f"cannot copy key {src} -> {dst}: {e}"
            ) from e
        written.append(dst)
    return written


# --- rotation keyring -------------------------------------------------------
# Graceful key rotation: a directory of ``<keyid>.key`` files alongside the
# legacy single key. The NEWEST file is the active key (new v2 seals embed its
# 8-byte id); every prior key is retained so v2 blobs sealed under it still
# decrypt, and legacy v1 blobs keep decrypting under _load_or_create_key().
# Rotation is therefore additive -- no existing data is rewritten or lost.


def _key_fingerprint(key: bytes) -> bytes:
    return hashlib.sha256(key).digest()[:_KEYID_BYTES]


def _keyring_dir() -> Path:
    # Derived from _key_path().parent so tests that monkeypatch _KEY_PATH (or set
    # HOME) relocate the keyring with it.
    return _key_path().parent / "at_rest.d"


def _read_keyring_key(path: Path) -> bytes:
    try:
        file_lock.ensure_private_file(path)
        key = bytes.fromhex(file_lock.atomic_read_text(path).strip())
    except (OSError, ValueError) as e:
        raise EncryptionUnavailable(f"cannot read at-rest key {path}: {e}") from e
    if len(key) != _KEY_BYTES:
        raise EncryptionUnavailable(f"at-rest key {path} is malformed")
    return key


def _active_keyring_key() -> tuple[bytes, bytes] | None:
    """``(key, keyid)`` of the newest keyring key, or None if the ring is empty
    (then sealing uses the legacy single-key v1 path, unchanged)."""
    try:
        keys = sorted(_keyring_dir().glob("*.key"))
    except OSError:
        return None
    if not keys:
        return None
    latest = max(keys, key=lambda p: p.stat().st_mtime)
    return _read_keyring_key(latest), bytes.fromhex(latest.stem)


def _resolve_key_by_id(keyid: bytes) -> bytes:
    """The key matching a v2 blob's ``keyid``: a keyring file, else the legacy
    key when its fingerprint matches (so a v1 deployment's key can also back v2)."""
    path = _keyring_dir() / (keyid.hex() + ".key")
    if path.exists():
        return _read_keyring_key(path)
    try:
        legacy = _load_existing_key()
        if _key_fingerprint(legacy) == keyid:
            return legacy
    except EncryptionUnavailable:
        pass
    raise EncryptionUnavailable(
        f"no at-rest key for key-id {keyid.hex()}: the key that sealed this data "
        "is not available (a rotated key was removed, or the wrong keyring)."
    )


def _rotation_intent(operation_id: str) -> Path:
    if not isinstance(operation_id, str) or re.fullmatch(r"[a-f0-9]{32,64}", operation_id) is None:
        raise EncryptionUnavailable("the key change request is invalid")
    return _key_path().parent / (".rotation-" + operation_id + ".intent")


def rotation_receipt(operation_id: str) -> str | None:
    """Read this exact additive change; never generate or install another key."""
    intent = _rotation_intent(operation_id)
    if not intent.exists():
        return None
    try:
        file_lock.ensure_private_file(intent)
        key = file_lock.atomic_read_bytes(intent)
        if len(key) != _KEY_BYTES:
            raise ValueError("invalid intent")
        keyid = _key_fingerprint(key).hex()
        destination = _keyring_dir() / (keyid + ".key")
        if not destination.exists():
            return None
        if not hmac.compare_digest(_read_keyring_key(destination), key):
            raise ValueError("key changed")
        return keyid
    except (OSError, ValueError) as exc:
        raise EncryptionUnavailable("the original key change could not be verified") from exc


def key_rotation_version() -> str:
    """Opaque local key-history metadata for a reviewed additive change."""
    entries = sorted(_keyring_dir().glob("*.key"))
    if len(entries) > 4096:
        raise EncryptionUnavailable("the local key history exceeds the maintenance allowance")
    legacy = _key_path()
    if legacy.exists():
        entries.append(legacy)
    # The content too: an in-place rewrite that keeps the size and restores the
    # modification time changes no stat fact, on POSIX (os.utime) or Windows
    # (st_ctime is the creation time there).
    source = []
    for item in entries:
        try:
            st = item.stat()
            content = file_lock.atomic_read_bytes(item)
        except OSError as e:
            raise EncryptionUnavailable("the local key history could not be read") from e
        source.append(f"{item.name}:{st.st_mtime_ns}:{st.st_size}:{hashlib.sha256(content).hexdigest()}")
    return hashlib.sha256("|".join(source).encode()).hexdigest()


def rotate_at_rest_key(*, operation_id: str | None = None, expected_version: str | None = None) -> str:
    """Serialize rotation and, when named, retain its exact private key intent.

    A repeated named request uses the same additive key. A process exit between
    key creation and dashboard receipt publication can be read back without
    performing another rotation. Raw intent material stays in the private key
    directory and is never returned, audited or stored in customer records.
    """
    if shared_authority_key_identity_required():
        raise EncryptionUnavailable("shared authority deployments require externally coordinated key rotation; a local key cannot replace them")
    if os.environ.get(_KEY_ENV):
        # Sealing prefers the keyring, so a local rotation would move every new
        # write off the injected key and onto a key file on disk.
        raise EncryptionUnavailable(
            "the at-rest key is injected via MAVERICK_ENCRYPTION_KEY; rotate it "
            "where it is managed, since a local rotation would put new data "
            "under a key stored on disk")
    _secure_key_dir()
    with file_lock.cross_process_lock(_key_path().parent / "rotation.lock", strict=True):
        if operation_id is not None:
            original = rotation_receipt(operation_id)
            if original:
                return original
        if expected_version is not None and not hmac.compare_digest(key_rotation_version(), expected_version):
            raise EncryptionUnavailable("the local key history changed after review")
        return _rotate_at_rest_key(operation_id=operation_id)


def _rotate_at_rest_key(*, operation_id: str | None = None) -> str:
    """Mint a new active at-rest key in the rotation keyring and return its id.

    Safe and additive: new seals immediately use the new key (v2 header), while
    all prior keys are retained so existing data stays readable -- no re-encrypt
    flag-day. Applies to the process-wide at-rest key (per-tenant envelope keys
    rotate via their own KMS). Takes effect for new seals right away.
    """
    if shared_authority_key_identity_required():
        raise EncryptionUnavailable(
            "shared authority deployments require externally coordinated key "
            "rotation; node-local rotation keys are refused"
        )
    if not _have_crypto():
        raise EncryptionUnavailable(
            "at-rest encryption needs the 'cryptography' package."
        )
    _secure_key_dir()
    d = _keyring_dir()
    try:
        file_lock.ensure_private_directory(d)
    except OSError as e:
        raise EncryptionUnavailable(f"cannot secure keyring dir {d}: {e}") from e
    if operation_id is not None:
        intent = _rotation_intent(operation_id)
        if not intent.exists():
            file_lock.atomic_create_bytes(intent, secrets.token_bytes(_KEY_BYTES))
        file_lock.ensure_private_file(intent)
        key = file_lock.atomic_read_bytes(intent)
        if len(key) != _KEY_BYTES:
            raise EncryptionUnavailable("the original key change material could not be verified")
    else:
        key = secrets.token_bytes(_KEY_BYTES)
    keyid = _key_fingerprint(key)
    path = d / (keyid.hex() + ".key")
    try:
        file_lock.atomic_create_text(path, key.hex())
    except FileExistsError:  # a named request may have committed before its reply
        if operation_id is None or not hmac.compare_digest(_read_keyring_key(path), key):
            raise EncryptionUnavailable("key-id collision; retry rotation") from None
    except OSError as e:
        raise EncryptionUnavailable(f"cannot write keyring key {path}: {e}") from e
    return keyid.hex()


def is_sealed(blob: bytes) -> bool:
    """True if ``blob`` was produced by :func:`seal` (carries a magic header).

    Recognises the v1 + v2 process-wide headers and the per-tenant envelope
    header, so strict-mode + TEXT-column detection treat sealed values as sealed."""
    return (
        blob[: len(_MAGIC)] == _MAGIC
        or blob[: len(_MAGIC_V2)] == _MAGIC_V2
        or blob[: len(_TENANT_MAGIC)] == _TENANT_MAGIC
        or blob[: len(_STREAM_MAGIC)] == _STREAM_MAGIC
    )


def seal(plaintext: bytes) -> bytes:
    """Encrypt with AES-256-GCM. Returns ``MAGIC || nonce || ciphertext+tag``.

    Raises :class:`EncryptionUnavailable` if crypto/key are missing (fail closed:
    the caller must not silently fall back to writing plaintext)."""
    # Per-tenant mode: route through the tenant's own data key. Output carries the
    # tenant magic header, so unseal()/is_sealed() handle it transparently and
    # globally-sealed data written before the switch still opens.
    if not _FORCE_DEPLOYMENT_KEY.get() and per_tenant_at_rest():
        from .paths import current_tenant_id
        from .tenant.kms import seal_for_tenant
        return seal_for_tenant(current_tenant_id(), plaintext)
    if not _have_crypto():
        raise EncryptionUnavailable(
            "at-rest encryption enabled but 'cryptography' is not installed "
            "(python -m pip install -e './packages/maverick-core[audit-signing]')"
        )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(_NONCE_BYTES)
    # If the rotation keyring has been initialised (an operator ran
    # `maverick encryption rotate`), seal under the active key and embed its id
    # (v2). Otherwise keep the legacy single-key v1 path byte-for-byte unchanged.
    active = (
        None
        if _FORCE_EXTERNAL_FLEET_KEY.get()
        else _active_keyring_key()
    )
    if active is not None:
        key, keyid = active
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        return _MAGIC_V2 + keyid + nonce + ct
    key = (
        _admitted_shared_key()
        if _FORCE_EXTERNAL_FLEET_KEY.get()
        else _load_or_create_key()
    )
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return _MAGIC + nonce + ct


def _unseal_with_key_cache(
    blob: bytes,
    key_cache: dict[tuple[str, bytes], object],
) -> bytes:
    """Decrypt a sealed blob. A blob *without* the magic header is returned
    unchanged — plaintext written before encryption was enabled (transparent
    migration). Raises :class:`EncryptionUnavailable` only when a genuinely
    sealed blob can't be opened."""
    if blob.startswith(_STREAM_MAGIC):
        from .sealed_stream import SealedStreamError, decode_stream

        try:
            return decode_stream(blob, lambda frame: _unseal_with_key_cache(frame, key_cache))
        except SealedStreamError as exc:
            raise EncryptionUnavailable("authenticated audit frames are invalid") from exc
    # A per-tenant envelope is opened with the tenant's data key regardless of
    # whether per-tenant mode is currently on (so reads keep working after the
    # mode is toggled). The current tenant must match the one it was sealed under
    # — GCM authentication fails otherwise, which is the cross-tenant guarantee.
    if blob[: len(_TENANT_MAGIC)] == _TENANT_MAGIC:
        if _FORCE_EXTERNAL_FLEET_KEY.get() or _FORCE_DEPLOYMENT_KEY.get():
            raise EncryptionUnavailable(
                "shared authority refuses tenant-envelope ciphertext"
            )
        from .paths import current_tenant_id
        from .tenant.kms import unseal_for_tenant
        return unseal_for_tenant(current_tenant_id(), blob)
    if not is_sealed(blob):
        return blob
    if not _have_crypto():
        raise EncryptionUnavailable(
            "found encrypted data but 'cryptography' is not installed"
        )
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # v2 (keyring): MAGIC_V2 || keyid(8) || nonce(12) || ct+tag. Resolve the key
    # by its embedded id so blobs sealed under a now-superseded key still open.
    if blob[: len(_MAGIC_V2)] == _MAGIC_V2:
        if _FORCE_EXTERNAL_FLEET_KEY.get():
            raise EncryptionUnavailable(
                "shared authority refuses node-local rotation-keyring ciphertext"
            )
        body = blob[len(_MAGIC_V2):]
        if len(body) < _KEYID_BYTES + _NONCE_BYTES + 16:
            raise EncryptionUnavailable(
                "sealed blob is truncated (too short for key-id + nonce + tag)"
            )
        keyid = body[:_KEYID_BYTES]
        nonce = body[_KEYID_BYTES:_KEYID_BYTES + _NONCE_BYTES]
        ct = body[_KEYID_BYTES + _NONCE_BYTES:]
        cache_key = ("v2", keyid)
        cipher = key_cache.get(cache_key)
        if cipher is None:
            cipher = AESGCM(_resolve_key_by_id(keyid))
            key_cache[cache_key] = cipher
        try:
            return cipher.decrypt(nonce, ct, None)
        except InvalidTag as e:
            raise EncryptionUnavailable(
                "cannot decrypt sealed data: wrong at-rest key or altered "
                "ciphertext (GCM authentication failed)"
            ) from e

    body = blob[len(_MAGIC):]
    # A sealed blob is MAGIC || 12-byte nonce || ciphertext+16-byte GCM tag.
    # Guard the length before slicing so a truncated blob raises the documented
    # EncryptionUnavailable, not a bare ValueError from AESGCM.
    if len(body) < _NONCE_BYTES + 16:
        raise EncryptionUnavailable(
            "sealed blob is truncated (too short to hold a nonce + GCM tag); "
            "the data is corrupt or not a Lightwork at-rest blob"
        )
    nonce, ct = body[:_NONCE_BYTES], body[_NONCE_BYTES:]
    cache_key = ("v1", b"")
    cipher = key_cache.get(cache_key)
    if cipher is None:
        key = (
            _admitted_shared_key()
            if _FORCE_EXTERNAL_FLEET_KEY.get()
            else _load_existing_key()
        )
        cipher = AESGCM(key)
        key_cache[cache_key] = cipher
    try:
        return cipher.decrypt(nonce, ct, None)
    except InvalidTag as e:
        # Wrong key (e.g. a rotated/restored key) or tampered ciphertext.
        # Honor the documented contract: surface EncryptionUnavailable rather
        # than leaking cryptography's InvalidTag, which callers that guard on
        # EncryptionUnavailable would not catch.
        raise EncryptionUnavailable(
            "cannot decrypt sealed data: wrong at-rest key or the ciphertext "
            "has been altered (GCM authentication failed)"
        ) from e


_BOUND_MAGIC = b"MVKBND1\n"   # context-bound: MAGIC || kind(1) || keyid(8) || nonce || ct


def _bound_aad(tenant: str | None, context: str) -> bytes:
    """Additional authenticated data: the tenant and the caller's context
    (e.g. ``attachment/<goal>/<name>``), length-prefixed so no two distinct
    pairs share an encoding."""
    # "t:" + the canonical (NFC) tenant id, or "n:" for no tenant, so a tenant
    # literally named "__default__" and the unbound deployment never share an AAD.
    if tenant:
        from .paths import canonical_tenant_id
        who = b"t:" + canonical_tenant_id(tenant).encode("utf-8")
    else:
        who = b"n:"
    parts = [who, context.encode("utf-8")]
    return b"maverick-bound/v1\x00" + b"".join(
        str(len(p)).encode("ascii") + b":" + p for p in parts)


def seal_bound(plaintext: bytes, context: str, *, portable: bool = False,
               bind_tenant: bool = True) -> bytes:
    """Seal bound to the current tenant AND ``context``.

    A blob copied to another tenant, another record or another field fails GCM
    authentication instead of decrypting there. Per-tenant mode seals under the
    tenant's own data key; otherwise the deployment (or active keyring) key, with
    its key id embedded so rotation keeps working. ``portable`` always uses the
    deployment/keyring key: per-tenant data keys live on one host, so anything
    read on another replica (the attachment S3 mirror) must not use them. The
    tenant binding is kept either way through the authenticated data.

    ``bind_tenant=False`` binds the context only (kind ``D``): for a store
    whose identity is the file itself (a per-tenant SQLite world), the
    request's tenant context is not part of the value's identity, and reads
    from another context must still open it."""
    if not _have_crypto():
        raise EncryptionUnavailable("at-rest encryption needs 'cryptography'")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from .paths import current_tenant_id
    tenant = current_tenant_id()
    if per_tenant_at_rest() and not portable:
        from .tenant.kms import tenant_dek
        kind, keyid, key = b"T", bytes(_KEYID_BYTES), tenant_dek(tenant)
    else:
        active = _active_keyring_key()
        if active is not None:
            key, keyid = active
        else:
            key = _load_or_create_key()
            keyid = _key_fingerprint(key)
        kind = b"K" if bind_tenant else b"D"
    if kind == b"D":
        tenant = None
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext, _bound_aad(tenant, context))
    return _BOUND_MAGIC + kind + keyid + nonce + ct


def is_bound(blob: bytes) -> bool:
    return blob[: len(_BOUND_MAGIC)] == _BOUND_MAGIC


def unseal_bound(blob: bytes, context: str,
                 key_cache: dict[tuple[str, bytes], object] | None = None) -> bytes:
    """Inverse of :func:`seal_bound`; raises :class:`EncryptionUnavailable` when
    the tenant, context, key or bytes do not match. ``key_cache`` lets a
    result-set reader resolve each key once per page."""
    if not is_bound(blob):
        raise EncryptionUnavailable("not a context-bound blob")
    if not _have_crypto():
        raise EncryptionUnavailable("found encrypted data but 'cryptography' is not installed")
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from .paths import current_tenant_id
    body = blob[len(_BOUND_MAGIC):]
    if len(body) < 1 + _KEYID_BYTES + _NONCE_BYTES + 16:
        raise EncryptionUnavailable("bound blob is truncated")
    kind, keyid = body[:1], body[1:1 + _KEYID_BYTES]
    nonce = body[1 + _KEYID_BYTES:1 + _KEYID_BYTES + _NONCE_BYTES]
    tenant = None if kind == b"D" else current_tenant_id()
    cache_key = ("bound:" + kind.decode("ascii", "replace") + ":" + (tenant or ""), keyid)
    cipher = key_cache.get(cache_key) if key_cache is not None else None
    if cipher is None:
        if kind == b"T":
            from .tenant.kms import tenant_dek
            key = tenant_dek(tenant)
        elif kind in (b"K", b"D"):
            if (_keyring_dir() / (keyid.hex() + ".key")).exists():
                key = _resolve_key_by_id(keyid)
            else:
                # The legacy single key: one load, then the fingerprint check
                # (a result-set read must load the key once, not once per
                # resolver layer).
                key = _load_existing_key()
                if _key_fingerprint(key) != keyid:
                    raise EncryptionUnavailable(
                        f"no at-rest key for key-id {keyid.hex()}: the key that "
                        "sealed this data is not available (a rotated key was "
                        "removed, or the wrong keyring)."
                    )
        else:
            raise EncryptionUnavailable("bound blob has an unknown key kind")
        cipher = AESGCM(key)
        if key_cache is not None:
            key_cache[cache_key] = cipher
    try:
        return cipher.decrypt(nonce, body[1 + _KEYID_BYTES + _NONCE_BYTES:],
                              _bound_aad(tenant, context))
    except InvalidTag as e:
        raise EncryptionUnavailable(
            "cannot open bound data: different tenant or context, wrong key, "
            "or altered bytes (GCM authentication failed)") from e


def unseal(blob: bytes) -> bytes:
    """Decrypt one sealed blob with a request-local key cache."""
    return _unseal_with_key_cache(blob, {})


def reseal(original: bytes, plaintext: bytes) -> bytes:
    """Authenticate a record and replace its content under the same envelope.

    This supports updating retained encrypted records after an encryption-mode
    toggle. It does not turn plaintext into ciphertext or migrate key identity.
    Authentication and deployment-key scope restrictions are the same as reads.
    """
    if not original.startswith((_MAGIC, _MAGIC_V2, _TENANT_MAGIC)):
        raise EncryptionUnavailable("record uses an unsupported encryption envelope")
    key_cache: dict[tuple[str, bytes], object] = {}
    _unseal_with_key_cache(original, key_cache)
    if original.startswith(_TENANT_MAGIC):
        from .paths import current_tenant_id
        from .tenant.kms import seal_for_tenant

        return seal_for_tenant(current_tenant_id(), plaintext)
    if original.startswith(_MAGIC_V2):
        keyid = original[len(_MAGIC_V2):len(_MAGIC_V2) + _KEYID_BYTES]
        header, cipher = _MAGIC_V2 + keyid, key_cache[("v2", keyid)]
    else:
        header, cipher = _MAGIC, key_cache[("v1", b"")]
    nonce = secrets.token_bytes(_NONCE_BYTES)
    return header + nonce + cipher.encrypt(nonce, plaintext, None)


def seal_text(text: str) -> bytes:
    return seal(text.encode("utf-8"))


def unseal_to_text(blob: bytes) -> str:
    return unseal(blob).decode("utf-8", errors="replace")


def encrypt(text: str) -> bytes:
    """Encrypt one UTF-8 field using the active at-rest/tenant key boundary.

    This small compatibility surface is intentionally typed and delegates to
    :func:`seal_text`; it does not add a second ciphertext format or weaken the
    fail-closed behavior of :func:`seal`.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    return seal_text(text)


def decrypt(blob: bytes) -> str:
    """Decrypt one field produced by :func:`encrypt` as UTF-8 text."""
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    return unseal_to_text(blob)


# --- TEXT-column helpers ---------------------------------------------------
# Seal a string into a single TEXT-storable token so a sensitive SQLite column
# (TEXT affinity) can hold ciphertext with no schema change. A value without the
# marker is treated as legacy plaintext (transparent migration).
_STR_PREFIX = "MVKAR1:"


# A context-bound TEXT token: ``MVKBND1:<context>:<base64(seal_bound)>``. The
# context (``table.column``) is carried in clear so a reader that does not
# know where the value came from can still open it, and it is also inside the
# GCM associated data, so rewriting the clear copy fails authentication.
_BOUND_STR_PREFIX = "MVKBND1:"
_CONTEXT_RE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*")


def _parse_bound_str(s: object) -> tuple[str, bytes] | None:
    """``(context, blob)`` for a structurally valid bound token, else None."""
    if not isinstance(s, str) or not s.startswith(_BOUND_STR_PREFIX):
        return None
    context, sep, payload = s[len(_BOUND_STR_PREFIX):].partition(":")
    if not sep or not _CONTEXT_RE.fullmatch(context):
        return None
    try:
        blob = base64.b64decode(payload, validate=True)
    except (ValueError, binascii.Error):
        return None
    if not is_bound(blob) or len(blob) < len(_BOUND_MAGIC) + 1 + _KEYID_BYTES + _NONCE_BYTES + 16:
        return None
    return context, blob


def is_bound_str(s: object) -> bool:
    """True only for structurally valid context-bound TEXT-column tokens."""
    return _parse_bound_str(s) is not None


def bound_str_context(s: object) -> str | None:
    """The ``table.column`` a bound token says it belongs to (unauthenticated
    until the token is opened), or None for anything else."""
    parsed = _parse_bound_str(s)
    return parsed[0] if parsed else None


def seal_bound_to_str(text: str, context: str, *, bind_tenant: bool = True) -> str:
    """Seal ``text`` bound to ``context`` (``table.column``) and, unless
    ``bind_tenant`` is False, the current tenant, as a TEXT-column token. See
    :func:`seal_bound`."""
    if not isinstance(context, str) or not _CONTEXT_RE.fullmatch(context):
        raise ValueError("seal context must look like 'table.column'")
    blob = seal_bound(text.encode("utf-8"), context, bind_tenant=bind_tenant)
    return _BOUND_STR_PREFIX + context + ":" + base64.b64encode(blob).decode("ascii")


def unseal_bound_from_str(s: str, context: str | None = None,
                          key_cache: dict[tuple[str, bytes], object] | None = None) -> str:
    """Open a bound token. With ``context`` the token must say it belongs
    there; without it the embedded context is used (and still authenticated).
    Raises :class:`EncryptionUnavailable` on any mismatch."""
    parsed = _parse_bound_str(s)
    if parsed is None:
        raise EncryptionUnavailable("not a context-bound token")
    embedded, blob = parsed
    if context is not None and context != embedded:
        raise EncryptionUnavailable(
            f"bound value belongs to {embedded!r}, not {context!r} (moved between "
            "columns or records)")
    return unseal_bound(blob, embedded, key_cache).decode("utf-8", errors="replace")


def is_sealed_str(s: object) -> bool:
    """Return True only for structurally valid sealed TEXT-column tokens
    (legacy ``MVKAR1:`` or context-bound ``MVKBND1:``).

    The marker prefix is public, so callers must not treat a value as encrypted
    just because it starts with ``MVKAR1:``.  A legacy plaintext value may collide
    with that marker (or an attacker may forge the prefix).  Such values are not
    sealed and must remain visible to strict-mode guards and migration.
    """
    if is_bound_str(s):
        return True
    if not isinstance(s, str) or not s.startswith(_STR_PREFIX):
        return False
    try:
        blob = base64.b64decode(s[len(_STR_PREFIX):], validate=True)
    except (ValueError, binascii.Error):
        return False
    return is_sealed(blob) and len(blob) >= len(_MAGIC) + _NONCE_BYTES + 16


def seal_to_str(text: str) -> str:
    """Seal ``text`` into ``'MVKAR1:' + base64(sealed)`` -- safe for a TEXT column."""
    return _STR_PREFIX + base64.b64encode(seal(text.encode("utf-8"))).decode("ascii")


def unseal_from_str(s: str) -> str:
    """Inverse of :func:`seal_to_str`.

    Strings without the marker are returned unchanged (legacy plaintext written
    before encryption was enabled). Because the marker is public and TEXT fields
    may also contain attacker-controlled plaintext while encryption is disabled,
    a marked value is only decrypted after its payload decodes to a structurally
    valid sealed blob. Marker collisions remain plaintext; authentic-looking
    sealed blobs still fail closed if decryption/authentication fails.
    """
    if is_bound_str(s):
        return unseal_bound_from_str(s)
    if not is_sealed_str(s):
        return s
    try:
        blob = base64.b64decode(s[len(_STR_PREFIX):], validate=True)
    except (ValueError, binascii.Error):
        return s
    if not is_sealed(blob) or len(blob) < len(_MAGIC) + _NONCE_BYTES + 16:
        return s
    return unseal(blob).decode("utf-8", errors="replace")


def unseal_many_from_str(values: list[str]) -> list[str]:
    """Decrypt TEXT-column tokens while resolving each key once per batch.

    Single-value integrity checks are preserved, but repeated config/key-file
    I/O is removed from encrypted result-set reads. The cache is discarded on
    return so rotations and tenant-context changes are observed by the next
    query.
    """
    key_cache: dict[tuple[str, bytes], object] = {}
    out: list[str] = []
    for value in values:
        if is_bound_str(value):
            out.append(unseal_bound_from_str(value, None, key_cache))
            continue
        if not is_sealed_str(value):
            out.append(value)
            continue
        try:
            blob = base64.b64decode(value[len(_STR_PREFIX):], validate=True)
        except (ValueError, binascii.Error):
            out.append(value)
            continue
        if not is_sealed(blob) or len(blob) < len(_MAGIC) + _NONCE_BYTES + 16:
            out.append(value)
            continue
        out.append(
            _unseal_with_key_cache(blob, key_cache).decode(
                "utf-8", errors="replace"
            )
        )
    return out


__all__ = [
    "at_rest_enabled",
    "per_tenant_at_rest",
    "is_sealed",
    "is_sealed_str",
    "seal",
    "unseal",
    "seal_text",
    "unseal_to_text",
    "seal_to_str",
    "unseal_from_str",
    "unseal_many_from_str",
    "rotate_at_rest_key",
    "backup_key_material",
    "deployment_key_scope",
    "deployment_at_rest_enabled",
    "external_fleet_key_scope",
    "require_shared_deployment_key_identity",
    "shared_authority_key_identity_required",
    "EncryptionUnavailable",
]
