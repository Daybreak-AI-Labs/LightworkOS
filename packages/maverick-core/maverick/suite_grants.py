"""Per-user department (suite) access grants: job-function scoping (kernel).

The dashboard's privilege RBAC (``maverick_dashboard.rbac``) answers "how MUCH
may this user do?"; this store answers the orthogonal "WHICH part of the
workforce may they use?" — a finance analyst granted ``{"finance", "tax"}``
works with Finance and Tax specialists, never Legal's.

This module is the KERNEL home of the store and its enforcement so that every
caller — the dashboard, the CLI, and any future networked surface — shares one
source of truth (:func:`ensure_suite_allowed` at the deploy/dispatch
chokepoints in :mod:`maverick.departments` and :mod:`maverick.fleet`).
``maverick_dashboard.suite_grants`` re-exports this module for backward
compatibility; the dashboard additionally layers SCIM-group-derived grants on
top at HTTP resolution time (see ``maverick_dashboard.auth.caller_suites``).

Safety invariants:
  * No/empty acting principal (host operator via the CLI, auth-off dashboard)
    -> unrestricted; every gate is a no-op — kernel rule 1, fail open.
  * A configured dashboard admin (``MAVERICK_DASHBOARD_ADMINS`` /
    ``[dashboard] admins``) is never scoped.
  * No stored grant -> unrestricted by default (opt-in scoping);
    ``[dashboard] default_suites`` flips that to deny-by-default.
  * The store is control-plane data: one GLOBAL file, never per-tenant.

Store: ``~/.maverick/dashboard-user-suites.json`` (0600),
``{principal: [suite, ...]}``. An explicit EMPTY list is a valid grant meaning
"no departments at all"; remove the entry to lift scoping.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path


class DepartmentAccessError(PermissionError):
    """The acting principal's department grant does not include this suite."""

    def __init__(self, principal: str, suite: str) -> None:
        self.principal = principal
        self.suite = suite
        super().__init__(
            f"principal {principal!r} is not permitted to use the "
            f"{suite!r} department"
        )


class SuiteGrantStoreError(RuntimeError):
    """Department policy exists but cannot be trusted or resolved safely."""


# Serializes a grants load-modify-save in-process; cross_process_lock in
# _locked() extends it across processes (multiple dashboard workers edit grants).
_GRANTS_LOCK = threading.Lock()


def _locked(path: Path):
    from contextlib import ExitStack

    from .authority_effects import authority_effect_fence
    from .file_lock import cross_process_lock, ensure_private_directory
    from .paths import maverick_home

    ensure_private_directory(maverick_home())
    ensure_private_directory(path.parent)
    with ExitStack() as stack:
        # Revoke departments under the same fence used by authority-bound
        # reads/effects, before taking the grant-store locks (RBAC lock order).
        stack.enter_context(authority_effect_fence())
        stack.enter_context(_GRANTS_LOCK)
        stack.enter_context(cross_process_lock(path))
        return stack.pop_all()


def store_path() -> Path:
    # maverick_home() honors MAVERICK_HOME, so the grant store shares a root
    # with the SCIM user/group stores it resolves alongside (a MAVERICK_HOME
    # deployment/backup keeps explicit grants and group grants together).
    from .paths import maverick_home
    return maverick_home() / "dashboard-user-suites.json"


def known_suites() -> frozenset[str]:
    """Every suite key a grant may name (the department catalog's key space)."""
    from .domain import SUITE_PREFIXES
    return frozenset(SUITE_PREFIXES.values())


def admin_principals() -> frozenset[str]:
    """The configured dashboard admins (never scoped by department grants).

    Mirrors ``maverick_dashboard.auth.is_dashboard_admin`` exactly — the
    ``MAVERICK_DASHBOARD_ADMINS`` env (comma-separated) overrides the
    ``[dashboard] admins`` config list — so the kernel gate and the dashboard
    gate can never disagree about who bypasses scoping."""
    env = (os.environ.get("MAVERICK_DASHBOARD_ADMINS") or "").strip()
    if env:
        return frozenset(a.strip() for a in env.split(",") if a.strip())
    try:
        from .config import config_source_errors, load_config

        cfg = load_config()
        if config_source_errors():
            return frozenset()
        dashboard = cfg.get("dashboard", {})
        if dashboard is None:
            dashboard = {}
        if not isinstance(dashboard, dict):
            return frozenset()
        raw = dashboard.get("admins", []) or []
    except Exception:  # malformed policy must never create a bypass principal
        return frozenset()
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return frozenset()
    return frozenset(str(a).strip() for a in raw if str(a).strip())


def is_admin_principal(principal: str) -> bool:
    return bool(principal) and principal in admin_principals()


def default_suites() -> frozenset[str] | None:
    """Suites for an authenticated user with NO explicit grant.

    ``None`` (the default when the key is absent) means unrestricted — scoping
    is opt-in per user. A present-but-invalid config source raises and blocks
    dispatch instead of silently widening access. Set
    ``[dashboard] default_suites = ["finance"]`` for deny-by-default; unknown
    suite keys in the list are ignored (the safe, narrowing direction)."""
    try:
        from .config import config_source_errors, load_config

        cfg = load_config()
        if config_source_errors():
            raise SuiteGrantStoreError(
                "department defaults unavailable: an active config source is invalid"
            )
        dashboard = cfg.get("dashboard", {})
        if dashboard is None:
            dashboard = {}
        if not isinstance(dashboard, dict):
            raise SuiteGrantStoreError("department defaults invalid: [dashboard] must be a table")
        if "default_suites" not in dashboard:
            return None
        raw = dashboard.get("default_suites")
    except SuiteGrantStoreError:
        raise
    except Exception as exc:
        raise SuiteGrantStoreError(f"department defaults unavailable: {exc}") from exc
    if not isinstance(raw, (list, tuple)):
        raise SuiteGrantStoreError("default_suites must be a list")
    if any(not isinstance(s, str) for s in raw):
        raise SuiteGrantStoreError("default_suites entries must be strings")
    if not raw:
        # An explicitly empty configured default is deny-all, distinct from the
        # absent key's backwards-compatible unrestricted posture.
        return frozenset()
    return frozenset(str(s) for s in raw) & known_suites()


def _load() -> dict[str, list[str]]:
    from .file_lock import atomic_read_text, ensure_private_directory, ensure_private_file
    from .paths import maverick_home

    p = store_path()
    ensure_private_directory(maverick_home())
    ensure_private_directory(p.parent)
    if not p.exists():
        return {}
    try:
        ensure_private_file(p)
        data = _decode_json_object(atomic_read_text(p))
    except SuiteGrantStoreError:
        raise
    except (OSError, ValueError) as exc:
        raise SuiteGrantStoreError(f"suite-grant store unreadable or corrupt: {exc}") from exc
    if not isinstance(data, dict):
        raise SuiteGrantStoreError("suite-grant store corrupt: top-level value must be an object")
    known = known_suites()
    out: dict[str, list[str]] = {}
    for principal, suites in data.items():
        if not isinstance(principal, str) or not principal.strip() or principal != principal.strip():
            raise SuiteGrantStoreError(
                "suite-grant store corrupt: principals must be non-blank trimmed strings"
            )
        if not isinstance(suites, list) or any(not isinstance(s, str) for s in suites):
            raise SuiteGrantStoreError(
                f"suite-grant store corrupt: suites for {principal!r} must be a string list"
            )
        unknown = set(suites) - known
        if unknown:
            raise SuiteGrantStoreError(
                f"suite-grant store corrupt: unknown suite(s) for {principal!r}"
            )
        out[principal] = sorted(set(suites))
    return out


def _decode_json_object(raw: str) -> object:
    def _reject_constant(value: str):
        raise ValueError(f"non-finite number {value!r}")

    def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate key {key!r}")
            out[key] = value
        return out

    try:
        return json.loads(raw, parse_constant=_reject_constant, object_pairs_hook=_object)
    except (TypeError, ValueError) as exc:
        raise SuiteGrantStoreError(f"suite-grant store corrupt: {exc}") from exc


def _write(data: dict[str, list[str]]) -> None:
    from .file_lock import atomic_write_text
    atomic_write_text(store_path(), json.dumps(data, indent=2, sort_keys=True))


def list_grants() -> dict[str, list[str]]:
    """All explicitly-scoped ``{principal: [suite, ...]}`` assignments."""
    return _load()


def get_grant(principal: str) -> frozenset[str] | None:
    """The principal's explicit grant, or ``None`` when they have no entry."""
    suites = _load().get((principal or "").strip())
    return None if suites is None else frozenset(suites)


# Additional grant sources (e.g. the dashboard's SCIM-group-derived grants)
# consulted AFTER the explicit store and BEFORE the configured default. Kept in
# the kernel so the deploy/dispatch gates and the dashboard HTTP gates resolve
# through the SAME chain and can never disagree.
_EXTRA_RESOLVERS: list = []


def register_grant_resolver(fn) -> None:
    """Register an extra grant source: ``fn(principal) -> iterable | None``.

    ``None`` means "no opinion" (fall through); an iterable of suite keys is a
    grant (validated against :func:`known_suites`). First non-None resolver
    wins, in registration order. Idempotent per function object; a resolver
    errors fail closed rather than silently widening an ungranted user to every
    department."""
    if fn not in _EXTRA_RESOLVERS:
        _EXTRA_RESOLVERS.append(fn)


def _fallback_suites(principal: str) -> frozenset[str] | None:
    """Resolve non-explicit grant sources for ``principal``.

    Kept separate from :func:`granted_suites` so removal can compare the
    current explicit restriction with the policy that would replace it before
    changing the store.
    """
    for fn in _EXTRA_RESOLVERS:
        try:
            derived = fn(principal)
        except Exception as exc:
            raise SuiteGrantStoreError(
                f"department grant resolver failed for {principal!r}: {exc}"
            ) from exc
        if derived is not None:
            return frozenset(str(s) for s in derived) & known_suites()
    return default_suites()


def granted_suites(principal: str) -> frozenset[str] | None:
    """The suites ``principal`` may use, or ``None`` for unrestricted.

    Resolution order: explicit stored grant, then any registered extra source
    (SCIM groups), then the configured default (:func:`default_suites`) —
    which is itself ``None`` unless an operator opted the deployment into
    deny-by-default."""
    explicit = get_grant(principal)
    if explicit is not None:
        return explicit
    return _fallback_suites(principal)


def _audit_grant_change(actor: str, principal: str, old, new) -> None:
    """One tamper-evident audit row per grant change, so who-granted-whom-what
    is provable rather than a silent JSON edit. Ordinary writer outages remain
    fail-soft; an explicit policy/custody refusal propagates."""
    from .audit import EventKind, audit_event

    audit_event(
        EventKind.ACCESS_GRANT_CHANGED, agent=actor or "local",
        actor=actor or "local", principal=principal, field="suites",
        tenant="", old=old, new=new,
    )


def set_suites(principal: str, suites: object, *, actor: str = "") -> None:
    """Scope ``principal`` to exactly ``suites`` (an iterable of suite keys)."""
    principal = (principal or "").strip()
    if not principal:
        raise ValueError("empty principal")
    if isinstance(suites, str) or not hasattr(suites, "__iter__"):
        raise ValueError("suites must be a list of suite keys")
    cleaned = {str(s).strip() for s in suites if str(s).strip()}
    unknown = cleaned - known_suites()
    if unknown:
        raise ValueError(f"unknown suite(s): {sorted(unknown)}")
    with _locked(store_path()):
        data = _load()
        old = data.get(principal)
        new = sorted(cleaned)
        if old == new:
            return
        prior = dict(data)
        data[principal] = new
        _write(data)
        from .audit import AuditRefused

        try:
            _audit_grant_change(actor, principal, old, new)
        except AuditRefused:
            try:
                _write(prior)
            except Exception as rollback_exc:
                raise SuiteGrantStoreError(
                    "audit refused suite-grant change and rollback failed"
                ) from rollback_exc
            raise


def remove_grant(principal: str, *, actor: str = "") -> None:
    """Remove an explicit override only when the fallback is no broader.

    With the historical unrestricted default, deleting ``["finance"]``
    silently granted every department.  Refuse that privilege expansion and
    require the administrator to save an explicit replacement (including an
    empty deny-all grant) instead.
    """
    principal = (principal or "").strip()
    with _locked(store_path()):
        data = _load()
        removed = data.get(principal)
        if removed is None:
            return
        fallback = _fallback_suites(principal)
        previous = frozenset(removed)
        if not is_admin_principal(principal) and (
            fallback is None or not fallback.issubset(previous)
        ):
            raise ValueError(
                "cannot remove this department override because the deployment "
                "default would broaden access; save an explicit replacement "
                "(or no departments) instead"
            )
        prior = dict(data)
        data.pop(principal)
        _write(data)
        from .audit import AuditRefused

        try:
            _audit_grant_change(actor, principal, removed, None)
        except AuditRefused:
            try:
                _write(prior)
            except Exception as rollback_exc:
                raise SuiteGrantStoreError(
                    "audit refused suite-grant removal and rollback failed"
                ) from rollback_exc
            raise


def suite_allowed_for(principal: str | None, suite: str | None) -> bool:
    """Whether ``principal`` may use department ``suite`` (kernel gate).

    ``principal`` None/empty — the host operator (CLI) or an auth-off
    dashboard — and configured admins are never scoped. ``suite`` None means
    a generic/legacy pack outside every department, never scoped."""
    if suite is None or not (principal or "").strip():
        return True
    principal = str(principal).strip()
    if is_admin_principal(principal):
        return True
    allowed = granted_suites(principal)
    return allowed is None or suite in allowed


def ensure_suite_allowed(principal: str | None, suite: str | None) -> None:
    """Raise :class:`DepartmentAccessError` unless the grant permits ``suite``."""
    if not suite_allowed_for(principal, suite):
        raise DepartmentAccessError(str(principal), str(suite))


__all__ = [
    "DepartmentAccessError", "SuiteGrantStoreError", "store_path", "known_suites", "default_suites",
    "admin_principals", "is_admin_principal", "register_grant_resolver",
    "list_grants", "get_grant", "granted_suites", "set_suites", "remove_grant",
    "suite_allowed_for", "ensure_suite_allowed",
]
