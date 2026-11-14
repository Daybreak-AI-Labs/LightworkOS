"""Per-tenant envelope encryption — a DEK per tenant, wrapped by a KMS KEK.

:mod:`maverick.crypto_at_rest` seals data with **one** process-wide key — correct
for a single-tenant box, wrong for a hosted multi-tenant store where one process
must not hold a master key that opens every tenant's data. This module adds the
standard envelope pattern:

  - each tenant has its own **Data Encryption Key** (DEK), used to AES-256-GCM
    its data at rest;
  - each DEK is stored only in **wrapped** form (encrypted by a **Key Encryption
    Key**, the KEK), under the tenant's own ``keys/dek.wrapped`` (chmod 600);
  - the KEK lives in a :class:`KMS`. The default :class:`LocalKMS` derives the
    KEK from the at-rest key material (or ``MAVERICK_KMS_KEK``); a cloud KMS
    (AWS/GCP/Vault/Azure) is a drop-in that implements ``wrap``/``unwrap`` so the KEK
    never leaves the HSM.

Rotating the KEK (re-wrap the same DEK) is instant and re-encrypts nothing;
rotating a DEK requires re-encrypting that tenant's data and is a separate op.
Opt-in and offline-testable. Requires the ``cryptography`` extra (AES-GCM).
"""
from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Protocol

from ..crypto_at_rest import EncryptionUnavailable, _have_crypto
from ..file_lock import (
    _windows_extended_path,
    atomic_create_bytes,
    atomic_read_bytes,
    atomic_write_bytes,
    ensure_private_directory,
    ensure_private_file,
)
from ..paths import data_dir

# Monotonic clock for cache expiry (immune to wall-clock jumps).
_now = time.monotonic

_DEK_BYTES = 32
_NONCE_BYTES = 12
_GCM_TAG_BYTES = 16
_WRAP_MAGIC = b"MVKDEK1\n"   # a wrapped DEK
_SEAL_MAGIC = b"MVKTEN1\n"   # a tenant-sealed blob


def _io_path(path: Path) -> Path:
    """Keep named-tenant key/config I/O reachable at supported path lengths."""
    return Path(_windows_extended_path(path)) if os.name == "nt" else path


class KMS(Protocol):
    """Key Encryption Key operations. ``wrap``/``unwrap`` a 32-byte DEK.

    ``context`` is authenticated metadata (for example tenant id and purpose)
    that must match on unwrap, preventing wrapped DEKs from being transplanted
    between tenants or uses.
    """

    def wrap(self, dek: bytes, *, context: bytes | None = None) -> bytes: ...
    def unwrap(self, wrapped: bytes, *, context: bytes | None = None) -> bytes: ...


def _aesgcm(key: bytes):
    if not _have_crypto():
        raise EncryptionUnavailable(
            "per-tenant KMS needs the 'cryptography' extra "
            "(python -m pip install -e './packages/maverick-core[audit-signing]')")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key)


def _gcm_seal(
    key: bytes,
    magic: bytes,
    plaintext: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ct = _aesgcm(key).encrypt(nonce, plaintext, associated_data)
    return magic + nonce + ct


def _gcm_open(
    key: bytes,
    magic: bytes,
    blob: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    from cryptography.exceptions import InvalidTag

    if blob[: len(magic)] != magic:
        raise EncryptionUnavailable("blob is not a Lightwork KMS envelope (bad magic)")
    body = blob[len(magic):]
    if len(body) < _NONCE_BYTES + _GCM_TAG_BYTES:
        raise EncryptionUnavailable("KMS envelope is truncated")
    nonce, ct = body[:_NONCE_BYTES], body[_NONCE_BYTES:]
    try:
        return _aesgcm(key).decrypt(nonce, ct, associated_data)
    except InvalidTag as e:
        raise EncryptionUnavailable(
            "cannot open KMS envelope: wrong key or altered ciphertext") from e


def _tenant_context(tenant_id: str | None, purpose: bytes) -> bytes:
    """Canonical AEAD/KMS context for tenant-bound envelopes."""
    tenant = (tenant_id or "__default__").encode("utf-8")
    return (
        b"maverick-tenant-kms/v1\x00"
        + purpose
        + b"\x00"
        + str(len(tenant)).encode("ascii")
        + b":"
        + tenant
    )


def _resolve_local_kek(*, create: bool = True) -> bytes:
    """The local KEK: ``MAVERICK_KMS_KEK`` (hex/base64, 32 bytes) if set, else a
    stable derivation from the at-rest master key — so no new key file to manage
    and rotating the at-rest key rotates the KEK.

    ``create=False`` is for reads: a missing at-rest key is an error, never a
    reason to mint one (a fresh key can open nothing that already exists)."""
    raw = os.environ.get("MAVERICK_KMS_KEK")
    if raw:
        from ..crypto_at_rest import _decode_injected_key
        kek = _decode_injected_key(raw)
        if len(kek) != _DEK_BYTES:
            raise EncryptionUnavailable(
                f"MAVERICK_KMS_KEK must decode to {_DEK_BYTES} bytes, got {len(kek)}")
        return kek
    from ..crypto_at_rest import _KEY_ENV, _key_path, _load_or_create_key, _read_key_file
    if not create and not os.environ.get(_KEY_ENV) and not _key_path().exists():
        raise EncryptionUnavailable(
            f"at-rest key missing at {_key_path()}: cannot unwrap a data key "
            "(restore the key; a new one would not open existing data)")
    master = _load_or_create_key() if create or os.environ.get(_KEY_ENV) else _read_key_file()
    # Domain-separated derivation so the KEK is distinct from the at-rest data key.
    return hashlib.sha256(b"maverick-kms-kek/v1\x00" + master).digest()


class LocalKMS:
    """KEK held in-process (derived from the at-rest key, or ``MAVERICK_KMS_KEK``).
    Wraps DEKs with AES-256-GCM. The default provider for self-hosted deploys."""

    def __init__(self, kek: bytes | None = None):
        # Resolved lazily: wrapping may create the at-rest key on first use,
        # unwrapping (a read) never does.
        if kek is not None and len(kek) != _DEK_BYTES:
            raise EncryptionUnavailable("KEK must be 32 bytes")
        self._kek = kek

    def _key(self, *, create: bool) -> bytes:
        if self._kek is None:
            kek = _resolve_local_kek(create=create)
            if len(kek) != _DEK_BYTES:
                raise EncryptionUnavailable("KEK must be 32 bytes")
            self._kek = kek
        return self._kek

    def wrap(self, dek: bytes, *, context: bytes | None = None) -> bytes:
        return _gcm_seal(self._key(create=True), _WRAP_MAGIC, dek, context)

    def unwrap(self, wrapped: bytes, *, context: bytes | None = None) -> bytes:
        return _gcm_open(self._key(create=False), _WRAP_MAGIC, wrapped, context)


def _kms_config_for(tenant_id: str | None) -> dict:
    """The ``[kms]`` section governing ``tenant_id``, resolved deterministically.

    Fleet BYOK: tenant A may pin AWS KMS and tenant B Vault, each in its own
    ``tenants/<id>/config.toml``. ``load_config`` only merges the *active*
    tenant's overlay, so a fleet operation (rotating tenant X while no context is
    set) would read the wrong ``[kms]``. This merges the named tenant's overlay
    explicitly over the global config, independent of the ambient context.
    """
    from ..config import (
        CONFIG_OVERLAY_ENV,
        _deep_merge_config,
        _load_config_file,
        config_path,
        dashboard_overrides_path,
        load_config,
    )
    if tenant_id is None:
        return dict((load_config() or {}).get("kms") or {})
    base: dict = {}
    try:
        base = _load_config_file(config_path()) or {}
        dash = dashboard_overrides_path()
        if dash.exists():
            base = _deep_merge_config(base, _load_config_file(dash))
        overlay = os.environ.get(CONFIG_OVERLAY_ENV)
        if overlay:
            base = _deep_merge_config(base, _load_config_file(Path(overlay).expanduser()))
    except Exception:  # pragma: no cover -- global config unreadable
        base = {}
    try:
        from ..paths import _tenant_segment, maverick_home
        overlay_path = _io_path(
            maverick_home() / "tenants" / _tenant_segment(tenant_id) / "config.toml"
        )
        merged = (_deep_merge_config(base, _load_config_file(overlay_path, interpolate=False))
                  if overlay_path.exists() else base)
        return dict((merged or {}).get("kms") or {})
    except Exception:
        # A named tenant's overlay is unreadable/malformed: fall back to the
        # GLOBAL config only -- never to the ambient load_config(), which would
        # merge a DIFFERENT (active) tenant's [kms] and wrap this tenant's DEK
        # under the wrong key / silently downgrade BYOK.
        return dict(base.get("kms") or {})


def _tenant_own_key_id(tenant_id: str | None) -> str | None:
    """The key id ``tenant_id`` pinned in ITS OWN ``tenants/<id>/config.toml``
    ``[kms]`` (BYOK), or ``None``.

    Only the tenant's own overlay counts: a key inherited from the global
    config is the operator's and keeps the documented "env wins over config"
    precedence. An unreadable overlay yields ``None`` (as ``_kms_config_for``
    falls back to global config), never another tenant's key.
    """
    if tenant_id is None:
        return None
    try:
        from ..config import _load_config_file
        from ..paths import _tenant_segment, maverick_home
        overlay_path = _io_path(
            maverick_home() / "tenants" / _tenant_segment(tenant_id) / "config.toml"
        )
        if not overlay_path.exists():
            return None
        key_id = ((_load_config_file(overlay_path, interpolate=False) or {}).get("kms") or {}).get("key_id")
    except Exception:
        return None
    return (str(key_id).strip() or None) if key_id else None


def get_kms(tenant_id: str | None = None) -> KMS:
    """The KMS provider for ``tenant_id``. ``[kms] provider`` selects it (per the
    tenant's own config overlay when given); default local.

    Passing ``tenant_id`` resolves that tenant's ``[kms]`` deterministically so
    per-tenant BYOK works regardless of the active context. ``None`` uses the
    ambient/global config (the single-tenant default, byte-for-byte unchanged).
    """
    cfg = _kms_config_for(tenant_id)
    provider = str(cfg.get("provider") or "local")
    if provider not in ("", "local"):
        # Cloud KMS (aws/gcp/vault/azure): the KEK stays in the customer's HSM (BYOK).
        # An unknown provider, or a missing SDK, raises EncryptionUnavailable
        # rather than silently falling back to in-process LocalKMS -- a configured
        # HSM-backed provider must never be downgraded to in-process key material
        # (fail-closed, consistent with crypto_at_rest). Callers surface this
        # (doctor's at-rest check, the audit-seal CLI) rather than writing plaintext.
        # The resolved cfg is passed so the backend uses THIS tenant's region/
        # address, and the tenant's OWN key_id is pinned so a server-wide
        # MAVERICK_KMS_KEY_ID can't wrap its DEK under the operator's key (BYOK).
        from ..kms_backends import build_cloud_kms
        return build_cloud_kms(provider, cfg, key_id=_tenant_own_key_id(tenant_id))
    return LocalKMS()


def _wrapped_dek_path(tenant_id: str | None):
    return _io_path(data_dir("keys", "dek.wrapped", tenant=tenant_id))


# (dek, expiry_monotonic). expiry is None for a permanent cache entry.
_dek_cache: dict[str, tuple[bytes, float | None]] = {}
_dek_lock = threading.Lock()


def _dek_cache_ttl() -> float:
    """Seconds a tenant DEK stays cached before it must be re-unwrapped by the
    KMS. ``0`` (default) = cache for the process lifetime, unchanged behavior. A
    positive TTL bounds how long a *revoked* cloud-KMS key keeps opening data:
    after it lapses the next access re-hits the KMS, which then fails closed.
    ``MAVERICK_KMS_DEK_CACHE_TTL`` env wins over ``[kms] dek_cache_ttl``."""
    raw = os.environ.get("MAVERICK_KMS_DEK_CACHE_TTL")
    if raw is None or raw.strip() == "":
        try:
            from ..config import load_config
            raw = (load_config() or {}).get("kms", {}).get("dek_cache_ttl")
        except Exception:  # pragma: no cover -- config never blocks key setup
            raw = None
    try:
        return max(0.0, float(raw)) if raw is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def tenant_dek(tenant_id: str | None, *, kms: KMS | None = None) -> bytes:
    """The tenant's Data Encryption Key (unwrapped). Loads the wrapped DEK, or
    generates + wraps + persists one on first use. Cached per tenant id (bounded
    by ``[kms] dek_cache_ttl`` so a revoked KMS key takes effect)."""
    cache_key = tenant_id or "__default__"
    with _dek_lock:
        cached = _dek_cache.get(cache_key)
        if cached is not None:
            dek, cached_at = cached
            # TTL is evaluated against the CURRENT setting on every read, not
            # frozen at write -- so raising the TTL (or revoking a cloud KEK)
            # bounds even a tenant that was warmed under TTL=0.
            ttl = _dek_cache_ttl()
            if ttl <= 0 or cached_at + ttl > _now():
                return dek
            _dek_cache.pop(cache_key, None)  # lapsed -> re-unwrap below
        # Per-tenant BYOK: resolve THIS tenant's KMS unless one was injected.
        resolved = kms is None
        kms = kms or get_kms(tenant_id)
        path = _wrapped_dek_path(tenant_id)
        ensure_private_directory(path.parent)
        context = _tenant_context(tenant_id, b"dek-wrap")
        if path.exists():
            ensure_private_file(path)
            dek = kms.unwrap(atomic_read_bytes(path), context=context)
            if len(dek) != _DEK_BYTES:
                raise EncryptionUnavailable("unwrapped DEK is malformed")
        else:
            if resolved and _kms_config_unreadable(tenant_id):
                # The [kms] section that chose the provider may have been lost;
                # a new DEK wrapped by the fallback local KEK would silently
                # downgrade a BYOK tenant for good.
                raise EncryptionUnavailable(
                    "cannot create a data key: KMS configuration is unreadable")
            dek = _generate_and_persist_dek(path, context, kms)
        _dek_cache[cache_key] = (dek, _now())
        return dek


def _kms_config_unreadable(tenant_id: str | None) -> bool:
    """Whether a configuration source that may hold ``tenant_id``'s ``[kms]``
    could not be read (``load_config`` then returns defaults)."""
    from ..config import _source_errors, config_source_errors
    if tenant_id is None:
        return bool(config_source_errors(include_tenant=True))
    from ..paths import _tenant_segment, maverick_home
    plain = maverick_home() / "tenants" / _tenant_segment(tenant_id) / "config.toml"
    # The error cache is keyed by the spelling the loader used: this module
    # reads the overlay through _io_path (extended form on Windows), while
    # load_config uses the extended form only for long paths. Check both.
    spellings = list(dict.fromkeys([plain, _io_path(plain)]))
    return bool(config_source_errors(include_tenant=False) or _source_errors(spellings))


def _generate_and_persist_dek(path, context: bytes, kms: KMS) -> bytes:
    """First-use DEK: generate, wrap, write atomically with O_EXCL.

    The ``_dek_lock`` only serializes threads in ONE process; the on-disk
    O_EXCL is the cross-process guard. If another process won the race
    (FileExistsError), discard our just-generated key and adopt the winner's
    persisted DEK -- otherwise the loser would seal data under a key that was
    never written and is unreadable everywhere else."""
    dek = secrets.token_bytes(_DEK_BYTES)
    ensure_private_directory(path.parent)
    wrapped = kms.wrap(dek, context=context)
    try:
        atomic_create_bytes(path, wrapped)
    except FileExistsError:
        ensure_private_file(path)
        winner = kms.unwrap(atomic_read_bytes(path), context=context)
        if len(winner) != _DEK_BYTES:
            raise EncryptionUnavailable("unwrapped DEK is malformed") from None
        return winner
    return dek


def seal_for_tenant(tenant_id: str | None, plaintext: bytes, *, kms: KMS | None = None) -> bytes:
    """AES-256-GCM ``plaintext`` under the tenant's DEK."""
    context = _tenant_context(tenant_id, b"tenant-data")
    return _gcm_seal(tenant_dek(tenant_id, kms=kms), _SEAL_MAGIC, plaintext, context)


def unseal_for_tenant(tenant_id: str | None, blob: bytes, *, kms: KMS | None = None) -> bytes:
    """Inverse of :func:`seal_for_tenant`."""
    context = _tenant_context(tenant_id, b"tenant-data")
    return _gcm_open(tenant_dek(tenant_id, kms=kms), _SEAL_MAGIC, blob, context)


def seal_text_for_tenant(tenant_id: str | None, text: str, **kw) -> bytes:
    return seal_for_tenant(tenant_id, text.encode("utf-8"), **kw)


def unseal_text_for_tenant(tenant_id: str | None, blob: bytes, **kw) -> str:
    return unseal_for_tenant(tenant_id, blob, **kw).decode("utf-8", errors="replace")


def _write_wrapped_dek(path, wrapped: bytes, tenant_id: str | None) -> None:
    """Atomically replace a tenant's wrapped-DEK file and drop its cache entry.

    A UNIQUE temp (not a fixed ``dek.wrapped.tmp``) so two concurrent rotations
    of the same tenant can't interleave writes into one file and leave a torn
    blob that neither KEK can unwrap -- each writes its own temp and the last
    os.replace wins atomically."""
    ensure_private_directory(path.parent)
    atomic_write_bytes(path, wrapped)
    with _dek_lock:
        _dek_cache.pop(tenant_id or "__default__", None)


def rotate_kek(tenant_id: str | None, *, old_kms: KMS, new_kms: KMS) -> None:
    """Re-wrap the tenant's existing DEK under a new KEK (instant; re-encrypts no
    data). The data-key is unchanged, so already-sealed data stays readable."""
    path = _wrapped_dek_path(tenant_id)
    ensure_private_directory(path.parent)
    if not path.exists():
        raise EncryptionUnavailable(f"no wrapped DEK for tenant {tenant_id!r} to rotate")
    ensure_private_file(path)
    context = _tenant_context(tenant_id, b"dek-wrap")
    dek = old_kms.unwrap(atomic_read_bytes(path), context=context)
    if len(dek) != _DEK_BYTES:
        raise EncryptionUnavailable("unwrapped DEK is malformed")
    _write_wrapped_dek(path, new_kms.wrap(dek, context=context), tenant_id)


def rotate_kek_idempotent(tenant_id: str | None, *, old_kms: KMS, new_kms: KMS) -> str:
    """Resumable single-tenant rotation: re-wrap old->new, but SKIP a tenant
    whose DEK already unwraps under ``new_kms`` (so a fleet rotation interrupted
    midway finishes cleanly on re-run). Returns ``"rotated"`` or ``"skipped"``;
    raises when neither KEK can open the wrapped DEK (corrupt / foreign key)."""
    path = _wrapped_dek_path(tenant_id)
    ensure_private_directory(path.parent)
    if not path.exists():
        raise EncryptionUnavailable(f"no wrapped DEK for tenant {tenant_id!r} to rotate")
    ensure_private_file(path)
    context = _tenant_context(tenant_id, b"dek-wrap")
    wrapped = atomic_read_bytes(path)
    try:  # already on the new KEK? -> idempotent skip, no write
        if len(new_kms.unwrap(wrapped, context=context)) == _DEK_BYTES:
            return "skipped"
    except Exception:
        pass  # not yet rotated (or new_kms can't open it) -> rotate below
    dek = old_kms.unwrap(wrapped, context=context)
    if len(dek) != _DEK_BYTES:
        raise EncryptionUnavailable("unwrapped DEK is malformed")
    _write_wrapped_dek(path, new_kms.wrap(dek, context=context), tenant_id)
    return "rotated"


#: Ids other code treats as sentinels (``paths.data_dir`` reads
#: ``"__active__"`` as the ambient tenant; ``"__default__"`` is the shared
#: store's KMS context), mirroring ``registry._RESERVED_IDS``.
_RESERVED_TENANT_IDS = frozenset({"__active__", "__default__"})

#: Report key for the un-namespaced (no tenant) DEK in fleet rotation reports.
#: Tenant ids are never empty, so it cannot collide with a named tenant.
SHARED_DEK_LABEL = ""


def wrapped_dek_holders() -> tuple[list[str | None], dict[str, str]]:
    """Every wrapped DEK on disk, by owner, for fleet rotation.

    The roster alone is not enough: it drops removed (restorable) tenants and
    knows nothing about the un-namespaced DEK or tenants used without a roster,
    and a rotation that skips a DEK leaves it wrapped under the old KEK.
    Returns ``(owners, unrecognised)``: ``None`` in ``owners`` is the
    un-namespaced DEK; ``unrecognised`` maps a tenant directory holding a DEK
    whose name does not decode to a tenant id, to the reason.
    """
    from urllib.parse import unquote_to_bytes

    from ..paths import _tenant_segment, maverick_home

    home = maverick_home()
    owners: list[str | None] = []
    unrecognised: dict[str, str] = {}
    if _io_path(home / "keys" / "dek.wrapped").exists():
        owners.append(None)
    root = home / "tenants"
    entries = sorted(root.iterdir()) if root.is_dir() else []
    for entry in entries:
        if not _io_path(entry / "keys" / "dek.wrapped").exists():
            continue
        try:
            tid = unquote_to_bytes(entry.name).decode("utf-8")
            ok = bool(tid) and _tenant_segment(tid) == entry.name
        except (UnicodeDecodeError, ValueError):
            ok = False
        if ok and tid in _RESERVED_TENANT_IDS:
            # A sentinel id resolves to the ambient/shared path, not this
            # directory: rotating it would report success and leave this DEK
            # under the old KEK.
            unrecognised[entry.name] = "tenant directory uses a reserved id; rotate it by hand"
        elif ok:
            owners.append(tid)
        else:
            unrecognised[entry.name] = "tenant directory name does not decode to a tenant id"
    return owners, unrecognised


def rotate_kek_fleet(*, old_kms_for, new_kms_for) -> dict[str, str]:
    """Rotate every provisioned tenant's wrapped DEK from its old KEK to its new
    KEK (fleet-wide key rotation). ``old_kms_for`` / ``new_kms_for`` are callables
    ``tenant_id -> KMS`` resolving each tenant's OLD and NEW KEK respectively.

    The two callables must resolve to the *different* key states explicitly --
    do NOT use ``get_kms(t)`` for both: it reads the tenant's *current* config,
    so once you've switched ``[kms]`` to the new provider it returns the new KEK
    for both arms (the unwrap then fails, or the rotation is a silent no-op).
    Build the old KMS from the prior key material directly, e.g.
    ``old_kms_for=lambda t: LocalKMS(old_kek)`` and
    ``new_kms_for=lambda t: get_kms(t)`` (new config already in place).

    Best-effort and isolated: one tenant's failure is recorded and does not abort
    the rest. **Check the report before retiring the old KEK** -- any
    ``"error: ..."`` entry means that tenant is still wrapped under the old KEK
    and would become unreadable if it is decommissioned. Returns ``{tenant_id:
    "rotated" | "error: <reason>"}``; the un-namespaced DEK is reported under
    :data:`SHARED_DEK_LABEL` and the resolvers receive ``None`` for it. Every
    wrapped DEK on disk is covered (:func:`wrapped_dek_holders`), not only the
    roster. Re-wrap only -- no data is re-encrypted."""
    owners, unrecognised = wrapped_dek_holders()
    report: dict[str, str] = {name: f"error: {why}" for name, why in unrecognised.items()}
    for tid in owners:
        label = SHARED_DEK_LABEL if tid is None else tid
        try:
            rotate_kek(tid, old_kms=old_kms_for(tid), new_kms=new_kms_for(tid))
            report[label] = "rotated"
        except Exception as e:
            report[label] = f"error: {e}"
    return report


def _clear_cache() -> None:
    """Drop the in-memory DEK cache (tests / after a rotation)."""
    with _dek_lock:
        _dek_cache.clear()


__all__ = [
    "KMS", "LocalKMS", "get_kms",
    "tenant_dek", "seal_for_tenant", "unseal_for_tenant",
    "seal_text_for_tenant", "unseal_text_for_tenant",
    "rotate_kek", "rotate_kek_idempotent", "rotate_kek_fleet",
]
