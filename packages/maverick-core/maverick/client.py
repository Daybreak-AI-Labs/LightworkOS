"""Client binding — one Lightwork deployment, exactly one enterprise client.

Lightwork is deployed **one instance per enterprise client** (never a shared,
hosted multi-tenant service). This module makes that binding explicit and
**fail-closed** so client data can never land in an ambiguous, un-scoped
location:

* the deployment declares its client via ``[client] id`` or
  ``MAVERICK_CLIENT_ID``;
* that id becomes the tenant **floor** (consumed by
  :func:`maverick.paths.current_tenant_id`), so every data path — world DB,
  audit chain + keys, cross-session memory, fleet memory — resolves under
  ``~/.maverick/tenants/<client>/...`` instead of a shared root. There is no
  un-scoped global location for operating client data to accumulate in. Minimal
  signed offboarding receipts intentionally survive outside an erased root;
* in **enforced** mode (``[client] enforce = true``, ``MAVERICK_CLIENT_ENFORCE``,
  or enterprise mode) a missing/invalid client id REFUSES to start — there is no
  silent fallback to the shared root.

Off by default (no client id configured) => legacy single-root behaviour,
byte-for-byte unchanged, so existing single-tenant installs are unaffected.

The client id is immutable for a deployment's lifetime, so it is resolved once
and cached; set ``MAVERICK_CLIENT_ID`` in the service unit / image so the hot
path (every ``data_dir`` call resolves the tenant floor) never parses config.
"""
from __future__ import annotations

import logging
import os
import re

from ._envparse import coerce_bool, is_truthy
from .client_erasure import (
    ClientErasureError,
    delete_windows_erase_target,
    hold_windows_erase_parents,
    windows_erase_target_identity,
)

log = logging.getLogger(__name__)

# A client id becomes the tenant path segment, so it must satisfy the tenant
# charset (paths._SAFE_TENANT_CHARS): digits/._- and LOWERCASE letters only.
# Lowercase is required because the id is a directory name: on a case-insensitive
# filesystem (macOS APFS, Windows NTFS) "Acme" and "acme" resolve to the SAME
# directory, so allowing mixed case would let two distinct client ids collide
# onto one data root — the one thing the per-client binding must prevent.
_CLIENT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

# Resolved once per process (the binding is immutable for a deployment). Tests
# reset via reset_client_cache().
_UNSET = object()
_cached: object = _UNSET
_strict_cached: object = _UNSET


class ClientBindingError(RuntimeError):
    """Raised when a client-bound deployment is started without a valid client id."""


def reset_client_cache() -> None:
    """Forget the cached client id (test hook; the id is immutable in prod)."""
    global _cached, _strict_cached
    _cached = _UNSET
    _strict_cached = _UNSET


def _raw_client_id() -> str:
    """The configured client id, unvalidated. ``MAVERICK_CLIENT_ID`` wins over
    ``[client] id``; empty string when neither is set."""
    raw = (os.environ.get("MAVERICK_CLIENT_ID") or "").strip()
    if not raw:
        try:
            from .config import config_source_errors, load_config

            cfg = load_config()
            if config_source_errors():
                raise ClientBindingError(
                    "client binding unavailable: an active config source is invalid"
                )
            client = cfg.get("client") or {}
            if not isinstance(client, dict):
                raise ClientBindingError("[client] must be a table")
            raw = str(client.get("id") or "").strip()
        except ClientBindingError:
            raise
        except Exception as exc:
            raise ClientBindingError(f"client binding unavailable: {exc}") from exc
    return raw


def _resolve() -> str | None:
    try:
        raw = _raw_client_id()
    except ClientBindingError:
        # Resilient on the hot path: a corrupt/unreadable config source must not
        # crash an explicitly diagnostic-only binding lookup or a command like
        # ``maverick config-lint`` whose whole job is to REPORT that corrupt
        # file. Production still fails closed at the startup guard
        # ``require_client_binding()``, which calls ``_raw_client_id()``
        # directly, and every trust/auth caller inspects ``config_source_errors``
        # itself -- so the fail-closed seam is preserved where it belongs.
        return None
    if not raw:
        return None
    if not _CLIENT_RE.fullmatch(raw):
        # Diagnostic resolution reports an invalid id as unbound. Storage path
        # resolution uses strict_client_id() and therefore still fails closed.
        log.warning("[client] id %r is invalid (want %s); ignoring it",
                    raw, _CLIENT_RE.pattern)
        return None
    return raw


def client_id() -> str | None:
    """The deployment's bound client id, or ``None`` (legacy shared root).

    ``MAVERICK_CLIENT_ID`` wins over ``[client] id``. Cached for the process.
    """
    global _cached
    if _cached is _UNSET:
        _cached = _resolve()
    return _cached  # type: ignore[return-value]


def strict_client_id() -> str | None:
    """Resolve the binding without turning errors into unbound legacy mode.

    ``client_id()`` intentionally remains resilient for diagnostics and path
    display. A database predicate is a security boundary, however, so corrupt
    or invalid configured identity must raise instead of becoming ``None``.
    """
    global _cached, _strict_cached
    if _strict_cached is not _UNSET:
        return _strict_cached  # type: ignore[return-value]
    if _cached is not _UNSET and _cached is not None:
        _strict_cached = _cached
        return _cached  # type: ignore[return-value]
    raw = _raw_client_id()
    if not raw:
        _strict_cached = None
        return None
    if not _CLIENT_RE.fullmatch(raw):
        raise ClientBindingError(
            f"[client] id {raw!r} is invalid: must match {_CLIENT_RE.pattern} "
            "(lowercase letters, digits, '.', '_', '-'; lowercase is required so "
            "the data directory can't collide with a differently-cased id on a "
            "case-insensitive filesystem). Refusing to continue unscoped."
        )
    _cached = raw
    _strict_cached = raw
    return raw


def client_binding_enforced() -> bool:
    """Is a client binding REQUIRED to operate?

    On via ``MAVERICK_CLIENT_ENFORCE``, ``[client] enforce = true``, or
    enterprise mode (a deployment handling a real client's sensitive data must
    be provably bound to that client). Off by default. One decision reads the
    configuration once (``config.single_read``)."""
    from .config import single_read

    with single_read():
        return _client_binding_enforced()


def _client_binding_enforced() -> bool:
    env = os.environ.get("MAVERICK_CLIENT_ENFORCE")
    if env is not None and env.strip() != "":
        return is_truthy(env)
    try:
        from .enterprise import enterprise_enabled
        if enterprise_enabled():
            return True
    except Exception:  # pragma: no cover
        pass
    try:
        from .config import load_config
        return coerce_bool(((load_config() or {}).get("client") or {}).get("enforce"))
    except Exception:
        return False


def require_client_binding() -> str | None:
    """Fail-closed startup guard. Returns the bound client id.

    Raises :class:`ClientBindingError` when the binding is enforced but no valid
    client id is configured — so a client-bound surface never serves from the
    un-scoped shared root by accident. A no-op (returns ``None``) when binding
    is not enforced.
    """
    # A configured-but-invalid id is an unambiguous misconfiguration of the
    # immutable binding. Reject it regardless of the enforcement toggle.
    cid = strict_client_id()
    if cid:
        return cid
    if client_binding_enforced():
        raise ClientBindingError(
            "client binding is enforced but no client id is configured. Set "
            "MAVERICK_CLIENT_ID (recommended, in the service unit) or "
            "[client] id in config. Refusing to start unbound so client data "
            "cannot land in the shared root."
        )
    return None


def data_root():
    """The resolved data root for this deployment (for doctor/diagnostics)."""
    from .paths import diagnostic_data_dir
    return diagnostic_data_dir()


def erase_client(*, keep_audit: bool = False, actor: str | None = None) -> dict:
    """Erase the bound client's on-node root, preserving signed evidence.

    Refuses deletion until a signed request and its verification key are safely
    saved outside the erased tree. ``keep_audit`` also records the operation in
    the retained client chain. Partial deletion raises instead of claiming
    success. Stop writers before offboarding: this observes the local root, not
    external databases, other workspace roots, or future writes by live services.
    """
    cid = strict_client_id()
    if not cid:
        raise ClientBindingError(
            "refusing to erase: no client is bound (this would target the shared "
            "root). Set MAVERICK_CLIENT_ID / [client] id first."
        )
    from .paths import tenant_scope

    # Bind both storage and the signing identity, restoring the caller's scope.
    with tenant_scope(tenant=cid):
        return _erase_client_bound(cid, keep_audit=keep_audit, actor=actor)


def _erase_client_bound(cid: str, *, keep_audit: bool, actor: str | None) -> dict:
    import getpass

    from . import audit
    from .client_erasure import ErasureReceipt
    from .ediscovery import active_matter_count
    from .federation import hold_state_file_closed
    from .file_lock import cross_process_lock, ensure_private_directory
    from .paths import data_dir, maverick_home

    # Erasing the whole client root also removes every matter ledger in it, so
    # any active legal matter stops the erasure before anything is deleted.
    try:
        held = active_matter_count()
    except Exception as exc:  # failure-policy: fail_closed -- an unreadable ledger holds the root
        raise ClientErasureError("Legal holds could not be checked, so nothing was erased.") from exc
    if held:
        raise ClientErasureError(
            "A legal hold is active in this workspace, so its data cannot be erased. "
            "Ask your records administrator to release the hold first."
        )

    # A selected workspace must never silently substitute for the bound client.
    root = data_dir(tenant=cid)
    home = maverick_home()
    try:
        ensure_private_directory(home)
        ensure_private_directory(root.parent)
        ensure_private_directory(root)
        if root.resolve().parent != (home.resolve() / "tenants"):
            raise ValueError("the client root is outside this installation")
        canonical_root = root.resolve()
        root_identity = _erase_root_identity(root, canonical_root)
    except (OSError, ValueError) as exc:
        raise ClientErasureError("The client data folder could not be verified. Nothing was erased.") from exc

    # Serialize cooperating erases using a lock that cannot erase itself.
    receipts = home / "client-erasure"
    entered = False
    try:
        ensure_private_directory(receipts)
        with cross_process_lock(receipts / f".erase-{cid}", strict=True):
            entered = True
            # The client's federation state file is inside the root being erased. Keep it closed
            # for the whole erase, so that no state call reopens it between the removals.
            with hold_state_file_closed():
                return _erase_client_locked(root, home, cid, keep_audit, actor or f"local:{getpass.getuser()}",
                                            ErasureReceipt, audit, canonical_root, root_identity)
    except ClientErasureError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        message = (
            "The erase could not be confirmed. Check the activity receipts and remaining data."
            if entered else "The activity receipt folder could not be prepared. Nothing was erased."
        )
        raise ClientErasureError(message) from exc


def _erase_root_identity(root, canonical_root):
    """An erase keeps its original directory authority even if paths change."""
    import stat

    if root.resolve() != canonical_root:
        raise ValueError("the client data folder was redirected")
    try:
        info = root.lstat()
    except FileNotFoundError:
        return None
    junction = getattr(root, "is_junction", None)
    if (
        root.is_symlink() or (callable(junction) and junction())
        or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        or not stat.S_ISDIR(info.st_mode)
    ):
        raise ValueError("the client data folder is no longer an ordinary directory")
    return info.st_dev, info.st_ino


def _require_erase_root_identity(root, canonical_root, expected):
    if _erase_root_identity(root, canonical_root) != expected:
        raise ValueError("the client data folder identity changed")


def _remove_client_path(path, windows_identity) -> int:
    """Return one for removed files/links, zero for ordinary directories."""
    if os.name == "nt":
        delete_windows_erase_target(path, windows_identity)
        return int(not windows_identity[2] or windows_identity[3])
    junction = getattr(path, "is_junction", None)
    if callable(junction) and junction():
        path.rmdir()  # remove the junction itself, never its target
        return 1
    if path.is_file() or path.is_symlink():
        path.unlink()
        return 1
    if path.is_dir():
        path.rmdir()
        return 0
    if os.path.lexists(path):  # a FIFO, socket or device node
        path.unlink()
        return 1
    raise FileNotFoundError("a prepared deletion target disappeared")


def _windows_target_identities(targets):
    return {p: windows_erase_target_identity(p) for p in targets} if os.name == "nt" else {}


def _require_preflight_targets_unchanged(before, after):
    for path, identity in before.items():
        # The audit signer atomically republishes its public key during receipt
        # creation. Its identity can change without moving customer content;
        # the second snapshot still pins the object that deletion will open.
        if (path.parent.name == "keys" and path.parent.parent.name == "audit"
                and path.suffix == ".pub" and path in after):
            continue
        if after.get(path) != identity:
            raise ValueError("a client data file changed during erase preflight")


def _erase_client_locked(root, home, cid, keep_audit, actor, receipt_type, audit,
                         canonical_root, root_identity) -> dict:
    import hashlib
    import json

    receipt = None
    try:
        _require_erase_root_identity(root, canonical_root, root_identity)
        targets = list(_erase_targets(root, keep_audit=keep_audit)) if root.exists() else []
        preflight_identities = _windows_target_identities(targets)
        relative = sorted(p.relative_to(root).as_posix() for p in targets)
        areas: dict[str, int] = {}
        for name in relative:
            area = name.split("/", 1)[0] if "/" in name else "(top level)"
            # Receipts outlive offboarding. Retain no customer-chosen folder
            # names or contents; the manifest digest commits to the inventory.
            if area not in {"audit", "memory", "fleet", "backups", "(top level)"}:
                area = "(other folders)"
            areas[area] = areas.get(area, 0) + 1
        detail = {"client_id": cid, "actor": actor, "keep_audit": keep_audit,
                  "client_root": root.relative_to(home).as_posix(),
                  "preflight_target_count": len(targets), "preflight_target_areas": areas,
                  "preflight_inventory_sha256": hashlib.sha256(json.dumps(relative).encode()).hexdigest()}
        receipt = receipt_type(home, detail)
        if keep_audit and audit.record(
            "client_erase_requested", agent="client-maintenance", _require_signed=True,
            event_id=receipt.id, **detail,
        ) is not True:
            raise OSError("the retained activity record was not saved")
        # First-use signing may provision verification material in the client
        # audit tree. Include it in deletion rather than leave a fresh key behind.
        _require_erase_root_identity(root, canonical_root, root_identity)
        targets = list(_erase_targets(root, keep_audit=keep_audit)) if root.exists() else []
        target_identities = _windows_target_identities(targets)
        _require_preflight_targets_unchanged(preflight_identities, target_identities)
        deletion = {"deletion_target_count": len(targets),
                    "deletion_manifest_sha256": hashlib.sha256(json.dumps(sorted(
                        p.relative_to(root).as_posix() for p in targets
                    )).encode()).hexdigest()}
        receipt.prepare(deletion)
        detail.update(deletion)
    except ClientErasureError:
        raise
    # failure-policy: fail_closed
    except Exception as exc:
        log.warning("client erase preflight refused", exc_info=True)
        raise ClientErasureError(
            "The data and signed activity record could not be prepared. Nothing was erased.",
            receipt_id=receipt.id if receipt is not None else "",
        ) from exc

    removed = 0
    failed_paths = set()
    for p in targets:
        try:
            if _erase_root_identity(root, canonical_root) != root_identity:
                raise ValueError("the client data folder identity changed")
        except (OSError, ValueError) as exc:
            failed_paths.add(root)
            log.warning("erase: stopped because the client data folder changed: %s", exc)
            break
        try:
            with hold_windows_erase_parents(root, p.parent, root_identity):
                # Reject an ancestor redirected outside the inspected client tree.
                p.parent.resolve().relative_to(canonical_root)
                removed += _remove_client_path(p, target_identities.get(p))
        except (OSError, ValueError) as exc:
            failed_paths.add(p)
            log.warning("erase: could not remove %s: %s", p, exc)
    try:
        if _erase_root_identity(root, canonical_root) != root_identity:
            raise ValueError("the client data folder identity changed")
        remaining = list(_erase_targets(root, keep_audit=keep_audit)) if root.exists() else []
        failed_paths.update(remaining)
    except (OSError, ValueError):
        failed_paths.add(root)
    failures = len(failed_paths)
    complete = failures == 0
    receipt.finish(complete=complete, removed=removed, failures=failures)
    if keep_audit:
        try:
            if audit.record(
                "client_erased" if complete else "client_erase_incomplete",
                agent="client-maintenance", _require_signed=True,
                event_id=receipt.id, removed=removed, failures=failures,
                status="completed" if complete else "incomplete", **detail,
            ) is not True:
                raise OSError("the retained completion event was not saved")
        # failure-policy: fail_closed
        except Exception as exc:
            raise ClientErasureError(
                "Deletion was attempted, but the retained activity record could not confirm it. "
                "The separate activity receipt records the observed result.",
                receipt_id=receipt.id, removed=removed,
            ) from exc
    if not complete:
        raise ClientErasureError(
            "Some client data could not be removed. Erasure is incomplete; check the remaining data.",
            receipt_id=receipt.id, removed=removed,
        )
    log.warning("client erase: removed %d path(s) under %s (keep_audit=%s)",
                removed, root, keep_audit)
    return {"client_id": cid, "root": str(root), "removed": removed,
            "kept_audit": keep_audit, "audit_event_id": receipt.id,
            "receipt_path": str(receipt.path)}


def _erase_targets(root, *, keep_audit: bool):
    """Every path :func:`erase_client` removes, deepest first."""
    def fail(error):
        raise error

    # os.walk does not follow symbolic links; prune Windows junctions too.
    from pathlib import Path
    targets = []
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        parent = Path(directory)
        for name in list(dirs):
            p = parent / name
            if keep_audit and parent == root and name == "audit":
                dirs.remove(name)
                continue
            targets.append(p)
            junction = getattr(p, "is_junction", None)
            if p.is_symlink() or (callable(junction) and junction()):
                dirs.remove(name)
        targets.extend(parent / name for name in files)
    yield from sorted(targets, key=lambda x: len(x.parts), reverse=True)


def erase_client_preview(*, keep_audit: bool = False) -> dict:
    """What :func:`erase_client` would remove, without removing anything.

    Counts the files per top-level area of the client's data root, walking
    exactly the paths the erase walks. Refuses unless a client is bound, like
    the erase itself.
    """
    cid = strict_client_id()
    if not cid:
        raise ClientBindingError(
            "refusing to preview an erase: no client is bound (this would "
            "target the shared root). Set MAVERICK_CLIENT_ID / [client] id first."
        )
    from .paths import data_dir
    root = data_dir(tenant=cid)
    by_area: dict[str, int] = {}
    files = 0
    if root.exists():
        for p in _erase_targets(root, keep_audit=keep_audit):
            if p.is_file() or p.is_symlink():
                rel = p.relative_to(root)
                area = rel.parts[0] if len(rel.parts) > 1 else "(top level)"
                by_area[area] = by_area.get(area, 0) + 1
                files += 1
    return {"client_id": cid, "files": files, "by_area": by_area,
            "kept_audit": keep_audit}


def status() -> dict:
    """Binding summary for ``maverick doctor`` / readiness."""
    cid = client_id()
    return {
        "client_id": cid,
        "enforced": client_binding_enforced(),
        "bound": bool(cid),
        "data_root": str(data_root()),
    }


__all__ = [
    "ClientBindingError",
    "ClientErasureError",
    "client_id",
    "strict_client_id",
    "client_binding_enforced",
    "require_client_binding",
    "reset_client_cache",
    "data_root",
    "erase_client",
    "erase_client_preview",
    "status",
]
