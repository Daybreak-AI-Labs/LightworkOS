"""Dashboard RBAC: admin-managed user roles (admin / operator / auditor / viewer).

This is the dashboard's *access-control* layer and is deliberately distinct from
the kernel's ``[roles]`` (``maverick.capability``), which only ATTENUATES an
agent's tool scope. Here a role GRANTS UI/API privilege, so it must never be
conflated with the kernel's attenuating roles.

Safety invariants (see maverick_dashboard.auth):
  * Meaningful only when an auth mode is on (OIDC / reverse-proxy / session).
    In no-token local mode ``caller_principal`` is None and every gate is a
    no-op — the local operator stays omnipotent, exactly as before.
  * A config-pinned bootstrap admin (``MAVERICK_DASHBOARD_ADMINS`` /
    ``[dashboard] admins``) is ALWAYS admin and is not stored here, so a wiped
    or tampered store can never lock every admin out.
  * The roster is control-plane data: one GLOBAL file, never per-tenant.

Store: ``~/.maverick/dashboard-users.json`` (0600), ``{principal: role}``.
Once any role is written, a private sibling marker
(``dashboard-users.json.present``) records that a roster exists. A missing
roster is then a refusal (:class:`RosterMissingError`), never a silent return
to the authenticated-user default. A configured bootstrap admin keeps access
and can restore the file from backup or explicitly start a new, empty roster
(:func:`reset_missing_rosters`).

The marker is written AFTER the roster, never before: a first roster write
that fails (disk full, a sharing violation) must leave nothing behind, or every
retry would find a marker with no roster and be refused. A roster without a
marker is the state older installations are already in; the next read records
it (:func:`_backfill_record`).
"""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path

# Built-in roles, ordered most-privileged first (SCIM group resolution and the
# admin UIs rely on the order). Custom roles extend -- never replace -- these:
# the builtins are immutable, and every permission a custom role can hold is
# one of the same four atoms the 1,400+ require_permission call sites gate on.
ROLES = ("admin", "operator", "auditor", "viewer")

# The permission atoms a role may grant. "view" is mandatory for every role:
# a principal who cannot even view has no working dashboard, which reads as
# breakage rather than policy.
PERMISSION_ATOMS = ("admin", "audit", "operate", "view")


class RbacStoreError(RuntimeError):
    """RBAC policy exists but cannot be trusted.

    Treating a damaged roster as empty restores the authenticated-user default
    and can promote a deliberately-demoted viewer back to operator. Readers and
    mutators therefore refuse present-but-invalid state instead of overwriting
    or broadening it.
    """


class RosterRollbackError(RbacStoreError):
    """A role change was refused by the activity log and putting the role list
    back failed, so the list may now hold the change."""


class RosterMissingError(RbacStoreError):
    """A role list was recorded on this installation, but the roster file is gone.

    Deleting, failing to restore, or misresolving the roster must not return
    every demoted person to the default role.
    """


# What the person who runs Lightwork can do, in the words the sign-in page, the
# Users page and the API refusal all share. An installation set up with the
# local owner has no administrator in configuration, and the owner's admin role
# lived only in the lost list, so the file-level step is part of the guidance.
ROSTER_RECOVERY = (
    "Restore the role list from a backup. Or have an administrator set up in configuration "
    "start a new, empty role list on the Users page. If none is set up, add the owner's email "
    "as user:name@company.com to [dashboard] admins in config.toml, or set "
    "MAVERICK_DASHBOARD_ADMINS, then restart Lightwork and sign in to start a new list."
)


class RecoveryAuthorityError(ValueError):
    """A role mutation would remove the final durable global administrator."""


# Serializes a roster load-modify-save in-process; cross_process_lock in
# _locked() extends it across processes (multiple dashboard workers edit roles).
_RBAC_LOCK = threading.Lock()


def _locked(path: Path):
    from contextlib import ExitStack

    from maverick.authority_effects import authority_effect_fence
    from maverick.file_lock import cross_process_lock, ensure_private_directory
    from maverick.paths import maverick_home

    ensure_private_directory(maverick_home())
    ensure_private_directory(path.parent)
    with ExitStack() as stack:
        stack.enter_context(authority_effect_fence())
        stack.enter_context(_RBAC_LOCK)
        stack.enter_context(cross_process_lock(path))
        return stack.pop_all()

# Permission lattice. The "audit" permission gates the audit-trail read surface
# (/api/v1/audit/*): the who-did-what-when record that can name principals, tool
# inputs and costs. It is held by "admin" and by the dedicated read-only
# "auditor" role -- separation of duties, so a compliance reviewer can read the
# audit log WITHOUT also holding operate/admin (run goals, change settings,
# manage users). "auditor" deliberately grants NOTHING operational: audit + view
# only. "operator"/"viewer" do NOT get "audit" -- reading the trail is a
# distinct grant, not implied by operate.
_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset({"admin", "audit", "operate", "view"}),  # users, settings, secrets, + all
    "operator": frozenset({"operate", "view"}),                 # run/cancel goals, approve, tools
    "auditor": frozenset({"audit", "view"}),                    # read audit trail (read-only)
    "viewer": frozenset({"view"}),                              # read-only
}


def store_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "dashboard-users.json"


def default_role() -> str:
    """Role for an authenticated user with no explicit assignment. Defaults to
    ``viewer``; grant operate or admin explicitly, or configure a different
    first-login role in ``[dashboard] default_role``."""
    try:
        from maverick.config import config_source_errors, load_config

        cfg = load_config()
        if config_source_errors():
            raise RbacStoreError("RBAC defaults unavailable: an active config source is invalid")
        dashboard = cfg.get("dashboard", {})
        if dashboard is None:
            dashboard = {}
        if not isinstance(dashboard, dict):
            raise RbacStoreError("RBAC defaults invalid: [dashboard] must be a table")
        if "default_role" not in dashboard:
            return "viewer"
        r = dashboard.get("default_role")
        if isinstance(r, str) and is_known_role(r):
            return r
        raise RbacStoreError("RBAC default_role is invalid")
    except RbacStoreError:
        raise
    except Exception as exc:
        raise RbacStoreError(f"RBAC defaults unavailable: {exc}") from exc
def permissions_for(role: str | None) -> frozenset[str]:
    name = role or ""
    builtin = _PERMISSIONS.get(name)
    if builtin is not None:
        return builtin
    if not name:
        return frozenset()
    try:
        rec = _load_custom().get(name)
    except RbacStoreError:
        # A corrupt custom-role store must DENY, not crash every request or --
        # worse -- broaden access through some fallback.
        from . import strict_reads

        if strict_reads.active():
            raise
        return frozenset()
    if rec is None:
        return frozenset()
    return frozenset(rec["permissions"])


# --- Custom roles -------------------------------------------------------------
# Admin-defined roles beyond the four builtins, e.g. "privacy-officer" =
# {audit, view} + operate. A custom role is a NAME plus a subset of the same
# four permission atoms; every gate in the product checks atoms, never role
# names (the /settings and /users lockout guard is the one name-keyed rule,
# and it guards the builtin "admin" only). Store:
# ``~/.maverick/dashboard-custom-roles.json`` (0600), global control-plane:
# ``{name: {"permissions": [...], "description": "..."}}``.

_ROLE_NAME = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")


def custom_roles_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "dashboard-custom-roles.json"


def _validate_custom_role(name: object, rec: object) -> tuple[str, dict]:
    if not isinstance(name, str) or not _ROLE_NAME.match(name):
        raise RbacStoreError(f"custom role store corrupt: invalid role name {name!r}")
    if name in ROLES:
        raise RbacStoreError(f"custom role store corrupt: {name!r} shadows a built-in role")
    if not isinstance(rec, dict):
        raise RbacStoreError(f"custom role store corrupt: record for {name!r} must be an object")
    perms = rec.get("permissions")
    if (
        not isinstance(perms, list)
        or not perms
        or any(p not in PERMISSION_ATOMS for p in perms)
        or len(set(perms)) != len(perms)
    ):
        raise RbacStoreError(f"custom role store corrupt: invalid permissions for {name!r}")
    if "view" not in perms:
        raise RbacStoreError(f"custom role store corrupt: {name!r} must grant view")
    description = rec.get("description", "")
    if not isinstance(description, str) or len(description) > 200:
        raise RbacStoreError(f"custom role store corrupt: invalid description for {name!r}")
    ordered = [p for p in PERMISSION_ATOMS if p in perms]
    return name, {"permissions": ordered, "description": description}


def _load_custom() -> dict[str, dict]:
    from maverick.file_lock import (
        atomic_read_text,
        ensure_private_directory,
        ensure_private_file,
    )
    from maverick.paths import maverick_home

    p = custom_roles_path()
    ensure_private_directory(maverick_home())
    ensure_private_directory(p.parent)
    if not p.exists():
        return {}
    try:
        ensure_private_file(p)
        data = _decode_json_object(atomic_read_text(p), label="custom role store")
    except RbacStoreError:
        raise
    except (OSError, ValueError) as exc:
        raise RbacStoreError(f"custom role store unreadable or corrupt: {exc}") from exc
    if not isinstance(data, dict):
        raise RbacStoreError("custom role store corrupt: top-level value must be an object")
    out: dict[str, dict] = {}
    for raw_name, raw_rec in data.items():
        name, rec = _validate_custom_role(raw_name, raw_rec)
        out[name] = rec
    return out


def _write_custom(data: dict[str, dict]) -> None:
    from maverick.file_lock import atomic_write_text

    atomic_write_text(custom_roles_path(), json.dumps(data, indent=2, sort_keys=True))


def list_custom_roles() -> dict[str, dict]:
    """All admin-defined roles: ``{name: {"permissions": [...], "description"}}``."""
    return {name: dict(rec) for name, rec in _load_custom().items()}


def known_roles() -> tuple[str, ...]:
    """Every assignable role: the builtins (most-privileged first, the order
    SCIM resolution and the admin UIs rely on) then custom roles by name."""
    try:
        custom = sorted(_load_custom())
    except RbacStoreError:
        custom = []
    return ROLES + tuple(custom)


def is_known_role(role: object) -> bool:
    if not isinstance(role, str):
        return False
    if role in ROLES:
        return True
    try:
        return role in _load_custom()
    except RbacStoreError:
        return False


def most_privileged(roles) -> str | None:
    """The most-privileged role among ``roles`` (builtin or custom), ranked by
    the permission atoms it grants -- the generalization of "ROLES is ordered
    most-privileged first" that SCIM group resolution used before custom
    roles. Deterministic: permission rank first, then name."""
    # Privilege order of the atoms: operate outranks audit, matching the
    # historical builtin order (admin > operator > auditor > viewer).
    privilege = ("admin", "operate", "audit", "view")
    best_rank: tuple | None = None
    best_role: str | None = None
    for role in roles:
        perms = permissions_for(role)
        if not perms:
            continue
        rank = tuple(atom in perms for atom in privilege)
        if (
            best_rank is None
            or rank > best_rank
            or (rank == best_rank and role < best_role)
        ):
            best_rank = rank
            best_role = role
    return best_role


def set_custom_role(
    name: str,
    permissions,
    description: str = "",
    *,
    actor: str = "",
) -> None:
    """Create or update an admin-defined role. Builtins are immutable."""
    name = (name or "").strip()
    if name in ROLES:
        raise ValueError("built-in roles cannot be redefined")
    cleaned_name, rec = None, None
    try:
        cleaned_name, rec = _validate_custom_role(
            name,
            {"permissions": list(permissions), "description": str(description or "")},
        )
    except RbacStoreError as exc:
        raise ValueError(str(exc)) from exc
    with _locked(custom_roles_path()):
        data = _load_custom()
        old = data.get(cleaned_name)
        if old == rec:
            return
        prior = {k: dict(v) for k, v in data.items()}
        data[cleaned_name] = rec
        _write_custom(data)
        _audit_role_change_with_rollback(
            actor,
            cleaned_name,
            "custom_role",
            "",
            (old or {}).get("permissions"),
            rec["permissions"],
            lambda: _write_custom(prior),
        )


def _custom_role_assignments(name: str) -> list[str]:
    """Where ``name`` is still in use (human-readable), for delete refusal."""
    used: list[str] = []
    used.extend(f"user {p}" for p, r in _load().items() if r == name)
    for tenant, members in _load_tenant().items():
        used.extend(f"user {p} in tenant {tenant}" for p, r in members.items() if r == name)
    try:
        from . import invites as _invites

        used.extend(
            f"pending invite {inv.email}"
            for inv in _invites.list_invites()
            if inv.role == name and inv.pending
        )
    except Exception:
        # The invite store being unreadable must not block role management;
        # roster and tenant assignments remain the hard refusals.
        pass
    return used


def delete_custom_role(name: str, *, actor: str = "") -> None:
    """Delete an admin-defined role. Refuses while any assignment still
    references it -- deleting an in-use role would turn every holder's next
    request into a corrupt-roster refusal."""
    name = (name or "").strip()
    if name in ROLES:
        raise ValueError("built-in roles cannot be deleted")
    with _locked(custom_roles_path()):
        data = _load_custom()
        old = data.get(name)
        if old is None:
            return
        used = _custom_role_assignments(name)
        if used:
            preview = ", ".join(used[:5]) + (", ..." if len(used) > 5 else "")
            raise ValueError(f"role {name!r} is still assigned ({preview}); reassign first")
        prior = {k: dict(v) for k, v in data.items()}
        data.pop(name)
        _write_custom(data)
        _audit_role_change_with_rollback(
            actor,
            name,
            "custom_role",
            "",
            old.get("permissions"),
            None,
            lambda: _write_custom(prior),
        )


def _presence_marker(path: Path) -> Path:
    """Private sibling recording that this roster has existed."""
    return path.with_name(path.name + ".present")


def _roster_recorded(path: Path) -> bool:
    try:
        _presence_marker(path).lstat()  # a dangling or odd entry still counts
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RbacStoreError(f"RBAC roster state unreadable: {exc}") from exc
    return True


def _record_roster(path: Path) -> None:
    """Durably note that ``path`` holds assigned roles (idempotent)."""
    from maverick.file_lock import atomic_write_text

    if not _roster_recorded(path):
        atomic_write_text(_presence_marker(path),
                          json.dumps({"schema": 1, "roster": path.name}, sort_keys=True))


def _missing_roster(path: Path, label: str) -> dict:
    if _roster_recorded(path):
        raise RosterMissingError(
            f"{label} is missing although this installation recorded one. {ROSTER_RECOVERY}"
        )
    return {}


def _backfill_record(path: Path) -> None:
    # Installations whose roster predates the marker gain it on first read.
    try:
        _record_roster(path)
    except (OSError, RbacStoreError) as exc:
        import logging

        logging.getLogger(__name__).warning("RBAC roster marker not recorded: %s", exc)


def _load() -> dict[str, str]:
    from maverick.file_lock import (
        atomic_read_text,
        ensure_private_directory,
        ensure_private_file,
    )
    from maverick.paths import maverick_home

    p = store_path()
    ensure_private_directory(maverick_home())
    ensure_private_directory(p.parent)
    if not p.exists():
        return _missing_roster(p, "The role list")
    try:
        ensure_private_file(p)
        data = _decode_json_object(atomic_read_text(p), label="RBAC roster")
    except RbacStoreError:
        raise
    except (OSError, ValueError) as exc:
        raise RbacStoreError(f"RBAC roster unreadable or corrupt: {exc}") from exc
    if not isinstance(data, dict):
        raise RbacStoreError("RBAC roster corrupt: top-level value must be an object")
    out: dict[str, str] = {}
    for principal, role in data.items():
        if not isinstance(principal, str) or not principal.strip() or principal != principal.strip():
            raise RbacStoreError("RBAC roster corrupt: principals must be non-blank trimmed strings")
        if not is_known_role(role):
            raise RbacStoreError(f"RBAC roster corrupt: invalid role for {principal!r}")
        out[principal] = role
    _backfill_record(p)
    return out


def _decode_json_object(raw: str, *, label: str) -> object:
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
        raise RbacStoreError(f"{label} corrupt: {exc}") from exc


def _write(data: dict[str, str]) -> None:
    # Unique temp + os.replace (0600): the fixed ".json.tmp" collided between
    # two concurrent dashboard workers (one os.replace moved it out from under
    # the other). Cross-process serialization of the RMW is in the mutators.
    from maverick.file_lock import atomic_write_text
    path = store_path()
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True))
    # After the roster, so a failed first write leaves no marker behind. If this
    # note cannot be written the roster still stands and the next read records it.
    _backfill_record(path)


def list_users() -> dict[str, str]:
    """All explicitly-assigned {principal: role} (bootstrap admins excluded)."""
    return _load()


def get_stored_role(principal: str) -> str | None:
    return _load().get((principal or "").strip())


def _durable_recovery_principals(data: dict[str, str]) -> frozenset[str]:
    """Principals that can recover the global dashboard control plane.

    Config-pinned bootstrap admins are immutable through this store.  Explicit
    assignments to the built-in ``admin`` role are the other durable recovery
    path: custom roles and SCIM-derived roles are intentionally not counted,
    because their mutable definitions/group memberships can disappear outside
    this roster mutation.
    """
    from maverick.suite_grants import admin_principals

    return admin_principals() | frozenset(
        principal for principal, role in data.items() if role == "admin"
    )


def _refuse_final_recovery_removal(
    before: dict[str, str],
    after: dict[str, str],
) -> None:
    """Refuse a transition that removes the final durable global admin."""
    if _durable_recovery_principals(before) and not _durable_recovery_principals(after):
        raise RecoveryAuthorityError(
            "cannot remove the final global administrator; assign another "
            "built-in admin or configure a bootstrap admin first"
        )


def _audit_role_change(actor: str, principal: str, field: str, tenant: str,
                       old, new) -> None:
    """One tamper-evident audit row per role change, so who-granted-whom-what
    is provable rather than a silent JSON edit. Ordinary writer outages remain
    fail-soft; a configured policy/custody refusal propagates."""
    from maverick.audit import EventKind, audit_event

    audit_event(
        EventKind.ACCESS_GRANT_CHANGED,
        agent=actor or "local",
        actor=actor or "local",
        principal=principal,
        field=field,
        tenant=tenant,
        old=old,
        new=new,
    )


def _audit_role_change_with_rollback(
    actor: str,
    principal: str,
    field: str,
    tenant: str,
    old,
    new,
    rollback,
) -> None:
    """Restore the prior roster before propagating an explicit refusal."""
    from maverick.audit import AuditRefused

    try:
        _audit_role_change(actor, principal, field, tenant, old, new)
    except AuditRefused:
        try:
            rollback()
        except Exception as rollback_exc:
            raise RosterRollbackError(
                "audit refused RBAC mutation and roster rollback failed"
            ) from rollback_exc
        raise


def set_role(principal: str, role: str, *, actor: str = "") -> None:
    principal = (principal or "").strip()
    if not principal:
        raise ValueError("empty principal")
    if not is_known_role(role):
        raise ValueError("unknown role")
    with _locked(store_path()):
        data = _load()
        old = data.get(principal)
        if old == role:
            return
        prior = dict(data)
        data[principal] = role
        _refuse_final_recovery_removal(prior, data)
        _write(data)
        _audit_role_change_with_rollback(
            actor,
            principal,
            "role",
            "",
            old,
            role,
            lambda: _write(prior),
        )


def remove_user(principal: str, *, actor: str = "") -> None:
    principal = (principal or "").strip()
    with _locked(store_path()):
        data = _load()
        prior = dict(data)
        removed = data.pop(principal, None)
        if removed is not None:
            _refuse_final_recovery_removal(prior, data)
            _write(data)
            _audit_role_change_with_rollback(
                actor,
                principal,
                "role",
                "",
                removed,
                None,
                lambda: _write(prior),
            )


# --- Per-tenant role memberships ---------------------------------------------
# A principal can hold a different role per tenant (e.g. admin of "acme",
# viewer of "globex"). This OVERRIDES the global stored role for that tenant
# only. The config-pinned bootstrap admin stays globally admin regardless, so
# tenant memberships can never lock every admin out. Store is a separate global
# control-plane file: ``{tenant: {principal: role}}``.


def tenant_store_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "dashboard-tenant-roles.json"


def _load_tenant() -> dict[str, dict[str, str]]:
    from maverick.file_lock import (
        atomic_read_text,
        ensure_private_directory,
        ensure_private_file,
    )
    from maverick.paths import maverick_home

    p = tenant_store_path()
    ensure_private_directory(maverick_home())
    ensure_private_directory(p.parent)
    if not p.exists():
        return _missing_roster(p, "The workspace role list")
    try:
        ensure_private_file(p)
        data = _decode_json_object(atomic_read_text(p), label="tenant RBAC roster")
    except RbacStoreError:
        raise
    except (OSError, ValueError) as exc:
        raise RbacStoreError(f"tenant RBAC roster unreadable or corrupt: {exc}") from exc
    if not isinstance(data, dict):
        raise RbacStoreError("tenant RBAC roster corrupt: top-level value must be an object")
    out: dict[str, dict[str, str]] = {}
    for tenant, members in data.items():
        if not isinstance(tenant, str) or not tenant.strip() or tenant != tenant.strip():
            raise RbacStoreError("tenant RBAC roster corrupt: tenant ids must be trimmed strings")
        if not isinstance(members, dict):
            raise RbacStoreError(f"tenant RBAC roster corrupt: members for {tenant!r} must be an object")
        clean: dict[str, str] = {}
        for principal, role in members.items():
            if not isinstance(principal, str) or not principal.strip() or principal != principal.strip():
                raise RbacStoreError(
                    f"tenant RBAC roster corrupt: invalid principal in {tenant!r}"
                )
            if not is_known_role(role):
                raise RbacStoreError(
                    f"tenant RBAC roster corrupt: invalid role for {principal!r}"
                )
            clean[principal] = role
        out[tenant] = clean
    _backfill_record(p)
    return out


def _write_tenant(data: dict[str, dict[str, str]]) -> None:
    from maverick.file_lock import atomic_write_text
    path = tenant_store_path()
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True))
    _backfill_record(path)  # after the roster, as in _write


def missing_rosters() -> list[str]:
    """Which recorded role lists are currently missing (``global``/``workspace``)."""
    found = []
    for name, path in (("global", store_path()), ("workspace", tenant_store_path())):
        if not path.exists() and _roster_recorded(path):
            found.append(name)
    return found


def reset_missing_rosters(*, actor: str = "") -> list[str]:
    """Explicitly start new, empty role lists where recorded ones are missing.

    Recovery for a configured bootstrap administrator when no backup can be
    restored. Every former assignment is gone, so people fall back to group
    roles or the configured default; the reset is audited. A present roster
    (even a corrupt one) is never replaced here.
    """
    from maverick.audit import AuditRefused

    reset = []
    for name, path in (("global", store_path()), ("workspace", tenant_store_path())):
        with _locked(path):
            if path.exists() or not _roster_recorded(path):
                continue
            from maverick.file_lock import atomic_create_text

            atomic_create_text(path, json.dumps({}, indent=2, sort_keys=True))
            try:
                _audit_role_change(actor, "*", f"{name}_roster_reset", "", "missing", "empty")
            except AuditRefused:
                try:
                    path.unlink()
                except OSError as rollback_exc:
                    raise RosterRollbackError(
                        "audit refused the role list reset and rollback failed"
                    ) from rollback_exc
                raise
            reset.append(name)
    return reset


def _tenant_removed(tenant: str) -> bool:
    from maverick.tenant.registry import tenant_retired

    if not (tenant or "").strip():
        return False
    try:
        return tenant_retired(tenant)
    except Exception as exc:
        raise RbacStoreError("workspace membership authority is unavailable") from exc


def tenant_role_scope_initialized() -> bool:
    """Whether workspace membership authority has ever been initialized.

    Keep the roster even when its last grant is revoked. A missing recorded
    roster raises rather than silently restoring installation-wide defaults.
    """
    _load_tenant()
    return tenant_store_path().exists()


def get_tenant_role(tenant: str, principal: str) -> str | None:
    """The principal's role within ``tenant``, or None if no membership."""
    if _tenant_removed(tenant):
        return None
    members = _load_tenant().get((tenant or "").strip(), {})
    return members.get((principal or "").strip())


def set_tenant_role(tenant: str, principal: str, role: str, *,
                    actor: str = "") -> None:
    tenant = (tenant or "").strip()
    principal = (principal or "").strip()
    if not tenant or not principal:
        raise ValueError("empty tenant or principal")
    if not is_known_role(role):
        raise ValueError("unknown role")
    with _locked(tenant_store_path()):
        if _tenant_removed(tenant):
            raise ValueError("removed workspace cannot receive members")
        data = _load_tenant()
        old = data.get(tenant, {}).get(principal)
        if old == role:
            return
        prior = json.loads(json.dumps(data))
        data.setdefault(tenant, {})[principal] = role
        _write_tenant(data)
        _audit_role_change_with_rollback(
            actor,
            principal,
            "tenant_role",
            tenant,
            old,
            role,
            lambda: _write_tenant(prior),
        )


def remove_tenant_role(tenant: str, principal: str, *, actor: str = "") -> None:
    tenant = (tenant or "").strip()
    principal = (principal or "").strip()
    removed = None
    with _locked(tenant_store_path()):
        data = _load_tenant()
        prior = json.loads(json.dumps(data))
        members = data.get(tenant)
        if members:
            removed = members.pop(principal, None)
            if removed is not None:
                if not members:
                    data.pop(tenant, None)
                _write_tenant(data)
                _audit_role_change_with_rollback(
                    actor,
                    principal,
                    "tenant_role",
                    tenant,
                    removed,
                    None,
                    lambda: _write_tenant(prior),
                )


def has_tenant_membership(principal: str) -> bool:
    """Whether ``principal`` holds a direct role in any workspace."""
    return bool(tenant_memberships(principal))


def tenant_memberships(principal: str) -> dict[str, str]:
    """Every workspace where ``principal`` holds a direct role: {workspace: role}."""
    principal = (principal or "").strip()
    return {tenant: members[principal] for tenant, members in sorted(_load_tenant().items())
            if principal in members}


def tenant_member_principals() -> set[str]:
    """Every principal holding a direct role in any workspace."""
    return {principal for members in _load_tenant().values() for principal in members}


def list_tenant_roles(tenant: str) -> dict[str, str]:
    """All {principal: role} memberships within ``tenant``."""
    if _tenant_removed(tenant):
        return {}
    return dict(_load_tenant().get((tenant or "").strip(), {}))


def clear_tenant_roles(tenant: str) -> int:
    """Revoke every direct membership when a workspace is removed.

    Tombstone admission closes access before this cleanup. Keep the old
    records in the workspace directory; only the global access roster changes.
    """
    from maverick.paths import _tenant_namespace_key

    key = _tenant_namespace_key(tenant)
    with _locked(tenant_store_path()):
        data = _load_tenant()
        names = [name for name in data if _tenant_namespace_key(name) == key]
        count = sum(len(data[name]) for name in names)
        if names:
            for name in names:
                del data[name]
            _write_tenant(data)
        return count


__all__ = [
    "ROLES", "PERMISSION_ATOMS", "ROSTER_RECOVERY", "RbacStoreError", "RosterMissingError",
    "RecoveryAuthorityError", "missing_rosters", "reset_missing_rosters",
    "store_path", "default_role",
    "permissions_for", "list_users", "get_stored_role", "set_role", "remove_user",
    "tenant_store_path", "get_tenant_role", "set_tenant_role",
    "remove_tenant_role", "list_tenant_roles", "clear_tenant_roles", "has_tenant_membership",
    "tenant_memberships", "tenant_member_principals",
    "custom_roles_path", "list_custom_roles", "known_roles", "is_known_role",
    "most_privileged", "set_custom_role", "delete_custom_role",
]
