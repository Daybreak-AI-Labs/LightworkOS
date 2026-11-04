"""Tenant-aware data paths — the multi-tenancy primitive.

Lightwork keeps its state under ``~/.maverick``. For multi-tenant deployments,
a *tenant* namespaces that state so one tenant's data (cross-session memory,
history, ...) is isolated from another's on disk.

The active tenant is resolved in order:

1. an explicit :func:`set_tenant` scope (a :class:`contextvars.ContextVar`, so
   concurrent async runs can each pin their own tenant safely);
2. the ``MAVERICK_TENANT`` environment variable;
3. none.

With **no** tenant, paths resolve to the legacy ``~/.maverick/<...>`` locations,
so single-tenant deployments are completely unchanged. With tenant ``t``, they
resolve under ``~/.maverick/tenants/<t>/<...>``.

Tenant-aware stores resolve their paths here, including the cross-session
**memory** store (the most leak-sensitive per-tenant store), the world model,
the audit log and the usage ledger.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import os
import threading
import unicodedata
from collections import OrderedDict
from pathlib import Path

_TENANT: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "maverick_tenant", default=None
)

# A tenant id becomes a path segment. Keep already-safe identifiers readable,
# but percent-encode every other UTF-8 byte so distinct tenant ids cannot
# collapse onto the same on-disk namespace.
_SAFE_TENANT_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
MAX_TENANT_SEGMENT_LENGTH = 200


class InvalidTenantError(ValueError):
    """Raised when a tenant id cannot be represented safely on disk."""


class TenantPolicyError(RuntimeError):
    """Tenant isolation policy cannot be resolved without risking data mixing."""


class TenantNamespaceCollision(InvalidTenantError):
    """Two tenant ids would address the same portable filesystem namespace."""


def _tenant_segment(tenant: str) -> str:
    # Normalise to NFC first so the same name in different Unicode normal forms
    # (e.g. NFC "josé" vs NFD "josé") maps to ONE on-disk namespace rather
    # than fragmenting a single tenant's data across two directories. A no-op for
    # ASCII ids (the common case), so existing lowercase-slug tenants are
    # byte-for-byte unchanged.
    tenant = unicodedata.normalize("NFC", tenant)
    if tenant in {".", ".."}:
        segment = "%2E" * len(tenant)
    else:
        segment = "".join(
            chr(byte) if chr(byte) in _SAFE_TENANT_CHARS else f"%{byte:02X}"
            for byte in tenant.encode("utf-8")
        )
    if len(segment) > MAX_TENANT_SEGMENT_LENGTH:
        raise InvalidTenantError("tenant id is too long")
    return segment


# A durable, immutable namespace claim prevents two processes (or two later
# runs) from assigning differently-cased ids to the same directory on Windows
# or a default case-insensitive macOS volume. Claims live outside ``tenants/``
# so deleting a tenant's data cannot release its old name for accidental reuse.
_TENANT_NAMESPACE_VERSION = 1
_TENANT_NAMESPACE_DIR = ".tenant-namespaces"
_TENANT_NAMESPACE_CACHE_MAX = 4096
_WINDOWS_DEVICE_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)
_tenant_namespace_cache: OrderedDict[tuple[str, str], str] = OrderedDict()
_tenant_namespace_lock = threading.Lock()


def canonical_tenant_id(tenant: str) -> str:
    """Return the portable canonical identity for a named tenant.

    Unicode normal forms are one identity (NFC), while display casing is
    retained. Casing aliases are rejected by :func:`bind_tenant_namespace`
    instead of silently changing an operator-facing id.
    """
    if not isinstance(tenant, str) or not tenant:
        raise InvalidTenantError("tenant id is required")
    canonical = unicodedata.normalize("NFC", tenant)
    # Check the identity before path encoding: a trailing space becomes ``%20``
    # in the portable segment and would otherwise bypass the Win32 alias guard.
    if canonical.endswith((".", " ")):
        raise InvalidTenantError("tenant id cannot end with a dot or space")
    segment = _tenant_segment(canonical)
    # Win32 strips trailing dots from path components and treats device names
    # as devices even when an extension is present. Reject these names on every
    # OS so a deployment can move its data without changing tenant identity.
    device_stem = segment.split(".", 1)[0].casefold()
    if device_stem in _WINDOWS_DEVICE_NAMES:
        raise InvalidTenantError("tenant id is a reserved filesystem name")
    return canonical


def _tenant_namespace_key(tenant: str) -> str:
    """Portable comparison key for an encoded tenant path component."""
    canonical = canonical_tenant_id(tenant)
    # The segment is ASCII-only: non-ASCII UTF-8 bytes are percent encoded.
    # casefold therefore exactly captures the case-insensitive path alias that
    # matters on Windows/default macOS without depending on the host OS.
    return _tenant_segment(canonical).rstrip(" .").casefold()


def _tenant_claim_path(home: Path, namespace_key: str) -> Path:
    digest = hashlib.sha256(namespace_key.encode("ascii")).hexdigest()
    # Sharding avoids putting millions of per-user tenant claims in one
    # directory on long-lived channel/fleet deployments.
    return home / _TENANT_NAMESPACE_DIR / digest[:2] / f"{digest}.json"


def _remember_tenant_namespace(cache_key: tuple[str, str], owner: str) -> None:
    _tenant_namespace_cache[cache_key] = owner
    _tenant_namespace_cache.move_to_end(cache_key)
    while len(_tenant_namespace_cache) > _TENANT_NAMESPACE_CACHE_MAX:
        _tenant_namespace_cache.popitem(last=False)


def _read_tenant_claim(path: Path) -> dict[str, object]:
    from .file_lock import atomic_read_text, ensure_private_file

    try:
        ensure_private_file(path)
        raw = atomic_read_text(path)
        if len(raw.encode("utf-8")) > 8192:
            raise ValueError("claim is too large")

        def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            out: dict[str, object] = {}
            for key, value in pairs:
                if key in out:
                    raise ValueError(f"duplicate key {key!r}")
                out[key] = value
            return out

        claim = json.loads(raw, object_pairs_hook=_object)
        if not isinstance(claim, dict):
            raise ValueError("claim must be an object")
        return claim
    except (OSError, TypeError, ValueError) as exc:
        raise TenantPolicyError(f"tenant namespace claim is untrusted: {path}") from exc


def _tenant_claim_owner(
    claim: dict[str, object], namespace_key: str, path: Path,
) -> str:
    try:
        raw_owner = claim.get("canonical_id")
        if not isinstance(raw_owner, str):
            raise ValueError("canonical_id must be a string")
        owner = canonical_tenant_id(raw_owner)
        if (
            raw_owner != owner
            or claim.get("version") != _TENANT_NAMESPACE_VERSION
            or claim.get("namespace_key") != namespace_key
            or claim.get("segment") != _tenant_segment(owner)
            or _tenant_namespace_key(owner) != namespace_key
        ):
            raise ValueError("claim fields are inconsistent")
        return owner
    except (TypeError, ValueError) as exc:
        raise TenantPolicyError(
            f"tenant namespace claim does not match its address: {path}"
        ) from exc


def tenant_namespace_reserved(tenant: str) -> bool:
    """Read durable name history without claiming or adopting a namespace."""
    canonical = canonical_tenant_id(tenant)
    key = _tenant_namespace_key(canonical)
    home = maverick_home()
    path = _tenant_claim_path(home, key)
    if path.exists():
        _tenant_claim_owner(_read_tenant_claim(path), key, path)
        return True
    root = home / "tenants"
    if root.exists():
        from .file_lock import ensure_private_directory
        ensure_private_directory(root)
        return any(entry.name.rstrip(" .").casefold() == key for entry in root.iterdir())
    return False


def bind_tenant_namespace(tenant: str, *, require_new: bool = False) -> str:
    """Atomically reserve and validate a tenant's portable path namespace.

    NFC/NFD spellings of the same id share one claim. A distinct spelling that
    aliases under case-insensitive or Win32 path rules is refused before any
    tenant data is opened. Existing exact-cased directories are adopted for
    backward compatibility; an existing differently-cased legacy directory is
    treated as a collision and never opened through the new id. Provisioning
    uses ``require_new``: any earlier claim/directory, including the same owner,
    refuses re-adoption. Ordinary retained-data reads remain unchanged.
    """
    canonical = canonical_tenant_id(tenant)
    segment = _tenant_segment(canonical)
    namespace_key = _tenant_namespace_key(canonical)
    home = maverick_home()
    home_key = os.path.normcase(os.path.abspath(os.fspath(home))).casefold()
    cache_key = (home_key, namespace_key)

    with _tenant_namespace_lock:
        owner = _tenant_namespace_cache.get(cache_key)
        if owner is not None and not require_new:
            if owner != canonical:
                raise TenantNamespaceCollision(
                    f"tenant id {tenant!r} aliases namespace owned by {owner!r}"
                )
            _tenant_namespace_cache.move_to_end(cache_key)
            return canonical

        from .file_lock import (
            atomic_create_text,
            ensure_private_directory,
        )

        # The home, tenant roster root, and immutable-claim root are all
        # Lightwork-owned confidentiality boundaries.
        ensure_private_directory(home)
        tenants_root = ensure_private_directory(home / "tenants")
        ensure_private_directory(home / _TENANT_NAMESPACE_DIR)
        claim_path = _tenant_claim_path(home, namespace_key)

        if claim_path.exists():
            claim = _read_tenant_claim(claim_path)
            owner = _tenant_claim_owner(claim, namespace_key, claim_path)
            if owner != canonical:
                raise TenantNamespaceCollision(
                    f"tenant id {tenant!r} aliases namespace owned by {owner!r}"
                )
            if require_new:
                raise TenantNamespaceCollision("Workspace identifier was used before; choose a new identifier. Retained data requires the recovery workflow.")
            _remember_tenant_namespace(cache_key, owner)
            return canonical

        # Upgrade path for homes created before namespace claims existed. Do
        # not let a new casing adopt an existing legacy tenant directory.
        for entry in tenants_root.iterdir():
            entry_key = entry.name.rstrip(" .").casefold()
            if require_new and entry_key == namespace_key:
                raise TenantNamespaceCollision("Workspace identifier has retained legacy data; choose a new identifier or use the recovery workflow.")
            if entry_key == namespace_key and entry.name != segment:
                raise TenantNamespaceCollision(
                    f"tenant id {tenant!r} aliases existing namespace {entry.name!r}"
                )

        payload = json.dumps(
            {
                "canonical_id": canonical,
                "namespace_key": namespace_key,
                "segment": segment,
                "version": _TENANT_NAMESPACE_VERSION,
            },
            ensure_ascii=True,
            sort_keys=True,
        )
        try:
            atomic_create_text(claim_path, payload)
            owner = canonical
        except FileExistsError:
            # Another process won the same namespace. Its immutable claim is
            # authoritative; only the same canonical identity may proceed.
            claim = _read_tenant_claim(claim_path)
            owner = _tenant_claim_owner(claim, namespace_key, claim_path)
            if require_new:
                raise TenantNamespaceCollision("Workspace identifier was concurrently reserved; choose a new identifier.") from None
        if owner != canonical:
            raise TenantNamespaceCollision(
                f"tenant id {tenant!r} aliases namespace owned by {owner!r}"
            )
        _remember_tenant_namespace(cache_key, owner)
        return canonical


def explicit_tenant_id() -> str | None:
    """Tenant selected by request/process context, excluding client binding."""
    t = _TENANT.get()
    if t:
        return t
    return os.environ.get("MAVERICK_TENANT", "").strip() or None


def implicit_tenant_id() -> str | None:
    """The deployment's own default tenant: the ``MAVERICK_TENANT`` process
    binding or the ``[client] id`` floor, ignoring any per-request scope.

    This is the tenant every task ran in before an operator created the first
    named workspace, so the tenant registry keeps it admitted rather than
    treating it as an unknown tenant once a roster exists.
    """
    env = os.environ.get("MAVERICK_TENANT", "").strip()
    if env:
        return env
    from .client import client_id
    return client_id()


def current_tenant_id() -> str | None:
    """The active raw tenant id, or ``None`` for the shared/legacy root.

    Explicit :func:`set_tenant` scope wins over the ``MAVERICK_TENANT`` env var.
    Unlike :func:`current_tenant`, this returns the operator-facing tenant id
    before path encoding so config lookups can use natural tenant keys.
    """
    explicit = explicit_tenant_id()
    if explicit:
        return explicit
    # Client binding: one deployment = one enterprise client. The configured
    # client id is the tenant FLOOR, so client data never resolves to an
    # un-scoped shared root. None when no client is bound (legacy single-root).
    from .client import client_id
    return client_id()


def current_tenant_id_strict() -> str | None:
    """Resolve tenant identity without the diagnostic hot-path fallback.

    Explicitly unbound legacy mode still returns ``None``. Invalid explicit
    tenant ids and corrupt/invalid client bindings raise, so security-sensitive
    backends cannot confuse resolution failure with legitimate unbound mode.
    """
    explicit = explicit_tenant_id()
    if explicit:
        _tenant_segment(explicit)  # validate before a backend builds a scope
        return explicit
    from .client import strict_client_id
    return strict_client_id()


def current_tenant() -> str | None:
    """The active tenant id (path-encoded), or ``None`` when truly unbound.

    This is the storage-safe resolver: invalid/corrupt client binding raises
    rather than silently selecting the shared root. Explicit tenant scope wins.
    """
    tenant = current_tenant_id_strict()
    if not tenant:
        return None
    return _tenant_segment(bind_tenant_namespace(tenant))


def current_tenant_diagnostic() -> str | None:
    """Best-effort tenant display for diagnostics; never use for storage."""
    tenant = current_tenant_id()
    return _tenant_segment(tenant) if tenant else None


def current_tenant_strict() -> str | None:
    """Strict path-encoded tenant, or ``None`` only when truly unbound."""
    tenant = current_tenant_id_strict()
    if not tenant:
        return None
    return _tenant_segment(bind_tenant_namespace(tenant))


def set_tenant(tenant: str | None):
    """Pin the active tenant for the current (async) context.

    Returns a token; pass it to :func:`reset_tenant` (or use try/finally) to
    restore the previous value. Concurrent runs on the same loop each see their
    own tenant because it lives in a ContextVar.
    """
    return _TENANT.set(tenant)


def reset_tenant(token) -> None:
    try:
        _TENANT.reset(token)
    except (ValueError, LookupError):  # pragma: no cover -- cross-context reset
        pass


def maverick_home() -> Path:
    """The base data dir (``~/.maverick``). NOT tenant-scoped; use
    :func:`data_dir` for tenant-isolated paths. ``MAVERICK_HOME`` may override
    the default for tests and custom deployments."""
    return Path(os.environ.get("MAVERICK_HOME", "~/.maverick")).expanduser()


def data_dir(*parts: str, tenant: str | None = "__active__") -> Path:
    """A data path under the (optionally tenant-scoped) home.

    With an active tenant ``t`` this is ``<home>/tenants/<t>/<parts...>``;
    with none it is the legacy ``<home>/<parts...>`` (single-tenant unchanged).
    Pass ``tenant=None`` to force the shared, un-namespaced location regardless
    of the active tenant.
    """
    if tenant == "__active__":
        segment = current_tenant()
    else:
        segment = (
            _tenant_segment(bind_tenant_namespace(tenant))
            if tenant
            else None
        )
    base = maverick_home()
    if segment:
        base = base / "tenants" / segment
    return base.joinpath(*parts)


def diagnostic_data_dir(*parts: str, tenant: str | None = "__active__") -> Path:
    """Best-effort path display that performs no storage admission.

    This exists only for doctor/config-lint output when a corrupt client config
    is itself what the operator needs to diagnose. Code that reads or writes
    state must use :func:`data_dir`, whose default resolution is fail-closed.
    """
    if tenant == "__active__":
        segment = current_tenant_diagnostic()
    else:
        segment = _tenant_segment(tenant) if tenant else None
    base = maverick_home()
    if segment:
        base = base / "tenants" / segment
    return base.joinpath(*parts)


def tenant_by_user_enabled() -> bool:
    """Opt-in, off by default. ``MAVERICK_TENANT_BY_USER=1`` or
    ``[tenancy] by_user = true`` makes the server isolate each channel user
    into their own tenant (so one user's cross-session memory can't leak to
    another). Off -> single shared tenant, behaviour unchanged."""
    env = os.environ.get("MAVERICK_TENANT_BY_USER")
    if env is not None and env.strip():
        value = env.strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
        if value in {"0", "false", "no", "off"}:
            return False
        raise TenantPolicyError("MAVERICK_TENANT_BY_USER must be a boolean")
    try:
        from .config import config_source_errors, load_config

        loaded = load_config()
        if config_source_errors():
            raise TenantPolicyError(
                "tenant isolation policy unavailable: an active config source is invalid"
            )
        cfg = loaded.get("tenancy") or {}
        if not isinstance(cfg, dict):
            raise TenantPolicyError("[tenancy] must be a table")
        raw = cfg.get("by_user", False)
        if not isinstance(raw, bool):
            raise TenantPolicyError("[tenancy] by_user must be a boolean")
        base = raw
    except TenantPolicyError:
        raise
    except Exception as exc:
        raise TenantPolicyError(f"tenant isolation policy unavailable: {exc}") from exc
    return base


@contextlib.contextmanager
def tenant_scope(
    *, channel: str | None = None, user_id: str | None = None, tenant: str | None = None
):
    """Pin the active tenant for the duration of the block, then restore it.

    No-op (yields with the tenant unchanged) unless an explicit ``tenant`` is
    given, or ``tenant_by_user_enabled()`` and a ``user_id`` is present — in
    which case the tenant is ``"<channel>:<user_id>"`` (sanitized). The reset
    on exit makes this safe for a server that handles messages sequentially on
    one task or concurrently across tasks.
    """
    if tenant is None and user_id is not None and tenant_by_user_enabled():
        tenant = f"{channel or 'unknown'}:{user_id}"
    if tenant is None:
        yield
        return
    token = set_tenant(tenant)
    try:
        yield
    finally:
        reset_tenant(token)


__all__ = [
    "current_tenant_id",
    "current_tenant_id_strict",
    "current_tenant",
    "current_tenant_diagnostic",
    "current_tenant_strict",
    "set_tenant",
    "reset_tenant",
    "maverick_home",
    "data_dir",
    "diagnostic_data_dir",
    "InvalidTenantError",
    "TenantNamespaceCollision",
    "TenantPolicyError",
    "MAX_TENANT_SEGMENT_LENGTH",
    "explicit_tenant_id",
    "tenant_by_user_enabled",
    "tenant_scope",
    "canonical_tenant_id",
    "bind_tenant_namespace",
    "tenant_namespace_reserved",
]
