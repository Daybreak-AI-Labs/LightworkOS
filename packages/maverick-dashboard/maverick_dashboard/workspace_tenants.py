"""Principal-scoped dashboard workspace selections.

The selected business tenant is navigation state, not authorization.  Store it
per authenticated principal and re-check active membership every time it is
bound.  Auth-off/static-token local mode keeps using the operator-wide
``[dashboard] active_tenant`` setting for backward compatibility.
"""
from __future__ import annotations

import json
import threading
from contextlib import ExitStack
from pathlib import Path

_LOCK = threading.Lock()
_SCHEMA = "lightwork.workspace-tenant-selections.v2"


class WorkspaceTenantStoreError(RuntimeError):
    """The principal selection store is present but cannot be trusted."""


def store_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "dashboard-workspace-tenants.json"


def _locked(path: Path) -> ExitStack:
    from maverick.authority_effects import authority_effect_fence
    from maverick.file_lock import cross_process_lock, ensure_private_directory

    ensure_private_directory(path.parent)
    with ExitStack() as stack:
        stack.enter_context(authority_effect_fence())
        stack.enter_context(_LOCK)
        stack.enter_context(cross_process_lock(path))
        return stack.pop_all()


def _load() -> dict[str, dict[str, object]]:
    from maverick.file_lock import atomic_read_text, ensure_private_file

    path = store_path()
    if not path.exists():
        return {}
    try:
        ensure_private_file(path)
        raw = json.loads(atomic_read_text(path))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise WorkspaceTenantStoreError(
            "workspace tenant selections are unreadable"
        ) from exc
    if not isinstance(raw, dict):
        raise WorkspaceTenantStoreError(
            "workspace tenant selections must be an object"
        )
    if raw.get("schema") == _SCHEMA:
        entries = raw.get("selections")
        if not isinstance(entries, dict) or set(raw) != {"schema", "selections"}:
            raise WorkspaceTenantStoreError(
                "workspace tenant selections have an invalid schema"
            )
    elif "schema" in raw or "selections" in raw:
        raise WorkspaceTenantStoreError(
            "workspace tenant selections use an unsupported schema"
        )
    else:
        # V1 stored ``{principal: tenant_id}``. Admit it as generation zero;
        # the next actual selection change writes V2 and starts generation one.
        entries = raw
    clean: dict[str, dict[str, object]] = {}
    for principal, value in entries.items():
        if isinstance(value, str):
            tenant_id, generation = value, 0
        elif isinstance(value, dict) and set(value) == {"tenant_id", "generation"}:
            tenant_id, generation = value["tenant_id"], value["generation"]
        else:
            raise WorkspaceTenantStoreError(
                "workspace tenant selections contain an invalid entry"
            )
        if (
            not isinstance(principal, str)
            or not principal.strip()
            or principal != principal.strip()
            or (tenant_id is not None and (
                not isinstance(tenant_id, str)
                or not tenant_id.strip()
                or tenant_id != tenant_id.strip()
            ))
            or type(generation) is not int
            or generation < 0
        ):
            raise WorkspaceTenantStoreError(
                "workspace tenant selections contain an invalid entry"
            )
        clean[principal] = {"tenant_id": tenant_id, "generation": generation}
    return clean


def get_selection(principal: str) -> str | None:
    name = str(principal or "").strip()
    if not name:
        return None
    record = _load().get(name)
    return None if record is None else record["tenant_id"]


def get_selection_binding(principal: str) -> tuple[str | None, int]:
    """Return the selection and monotonic generation used by queued approvals."""
    name = str(principal or "").strip()
    if not name:
        return None, 0
    record = _load().get(name)
    if record is None:
        return None, 0
    return record["tenant_id"], record["generation"]


def set_selection(principal: str, tenant_id: str | None) -> None:
    """Set or clear one principal's preference without granting membership."""
    from maverick.file_lock import atomic_write_text

    name = str(principal or "").strip()
    if not name:
        raise ValueError("authenticated principal required")
    selected = None if tenant_id is None else str(tenant_id).strip()
    if tenant_id is not None and not selected:
        raise ValueError("tenant id cannot be empty")
    path = store_path()
    with _locked(path):
        if selected is not None:
            from maverick.tenant.registry import tenant_retired

            if tenant_retired(selected):
                raise ValueError("removed workspace cannot be selected")
        data = _load()
        previous = data.get(name, {"tenant_id": None, "generation": 0})
        if previous["tenant_id"] == selected:
            return
        data[name] = {
            "tenant_id": selected,
            "generation": int(previous["generation"]) + 1,
        }
        atomic_write_text(path, json.dumps({
            "schema": _SCHEMA,
            "selections": data,
        }, indent=2, sort_keys=True))


def clear_tenant_selections(tenant_id: str) -> int:
    """Clear stale navigation and invalidate queued selection generations."""
    from maverick.file_lock import atomic_write_text
    from maverick.paths import _tenant_namespace_key

    key = _tenant_namespace_key(tenant_id)
    path = store_path()
    with _locked(path):
        data = _load()
        changed = 0
        for entry in data.values():
            selected = entry["tenant_id"]
            if selected is not None and _tenant_namespace_key(selected) == key:
                entry["tenant_id"] = None
                entry["generation"] = int(entry["generation"]) + 1
                changed += 1
        if changed:
            atomic_write_text(path, json.dumps({
                "schema": _SCHEMA,
                "selections": data,
            }, indent=2, sort_keys=True))
        return changed


def principal_can_select(principal: str, tenant_id: str) -> bool:
    """Membership (or global admin authority) required to select a tenant."""
    from . import rbac
    from .auth import global_role_for_principal

    role = global_role_for_principal(principal)
    if "admin" in rbac.permissions_for(role):
        return True
    return rbac.get_tenant_role(tenant_id, principal) is not None


def accessible_tenant_ids(principal: str) -> frozenset[str] | None:
    """Return visible memberships, or ``None`` for global tenant admins."""
    from . import rbac
    from .auth import global_role_for_principal

    role = global_role_for_principal(principal)
    if "admin" in rbac.permissions_for(role):
        return None
    try:
        # Tenant ids are registry identifiers, so iterating the active registry
        # avoids exposing names from tenants the caller cannot access.
        from maverick.tenant.registry import list_tenants

        return frozenset(
            record.id
            for record in list_tenants()
            if rbac.get_tenant_role(record.id, principal) is not None
        )
    except Exception as exc:
        raise WorkspaceTenantStoreError(
            "workspace tenant memberships are unavailable"
        ) from exc


__all__ = [
    "WorkspaceTenantStoreError",
    "accessible_tenant_ids",
    "get_selection",
    "get_selection_binding",
    "clear_tenant_selections",
    "principal_can_select",
    "set_selection",
    "store_path",
]
