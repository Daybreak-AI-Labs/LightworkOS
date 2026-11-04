"""Explain the same current role resolution used by dashboard authorization."""
from __future__ import annotations

import hashlib
import json


def role(principal, *, installation=False, without_explicit=False):
    from maverick.paths import current_tenant_id

    from . import auth, rbac, scim_groups, strict_reads

    if not principal:
        return {"role": None, "source": "Local installation authority", "owner": "Installation administrator"}
    if scim_groups.active_for_principal(principal) is False:
        return {"role": None, "source": "Deactivated identity", "owner": "Identity administrator"}
    if auth.is_dashboard_admin(principal):
        return {"role": "admin", "source": "Pinned installation administrator", "owner": "Installation administrator"}
    tenant = current_tenant_id()
    if tenant and not installation:
        membership = rbac.get_tenant_role(tenant, principal)
        if membership:
            return {"role": membership, "source": "Current workspace membership", "owner": "Workspace administrator"}
    explicit = rbac.get_stored_role(principal) if not without_explicit else None
    if explicit:
        return {"role": explicit, "source": "Explicit installation role", "owner": "Installation administrator"}
    try:
        with strict_reads.strict():
            group = scim_groups.role_for_principal(principal)
    except Exception:
        if strict_reads.active():
            raise
        return {"role": None, "source": "Sign-in group policy unavailable", "owner": "Identity or installation administrator"}
    if group:
        return {"role": group, "source": "Verified sign-in group mapping", "owner": "Identity or installation administrator"}
    if rbac.tenant_role_scope_initialized():
        from maverick.paths import tenant_by_user_enabled

        if not installation and tenant_by_user_enabled() and tenant == f"api:{principal}":
            return {"role": rbac.default_role(), "source": "Per-user workspace default", "owner": "Installation administrator"}
        return {"role": None, "source": "No installation role or selected workspace membership", "owner": "Installation administrator"}
    return {"role": rbac.default_role(), "source": "Configured first-login default", "owner": "Installation administrator"}


def standard_role(principal):
    from . import rbac
    from .identity_format import role_label
    value = role(principal, installation=True, without_explicit=True)
    value["permissions"] = sorted(rbac.permissions_for(value["role"]))
    value["label"] = role_label(value["role"]) if value["role"] else "No active role"
    value["revision"] = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    return value


def role_descriptions() -> dict[str, str]:
    """A plain sentence for every assignable role, built-in and custom.

    Custom roles read as their saved description plus the powers their
    permission atoms grant (the same atoms every permission check reads)."""
    from . import rbac
    from .identity_format import role_description
    try:
        custom = rbac.list_custom_roles()
    except rbac.RbacStoreError:
        custom = {}
    return {name: role_description(name, rbac.permissions_for(name),
                                   (custom.get(name) or {}).get("description", ""))
            for name in rbac.known_roles()}


def denial(request, permission, *, installation=False):
    from . import auth
    from .identity_format import role_label
    try:
        current = role(auth._authorization_principal(request), installation=installation)
        name = role_label(current["role"]) if current["role"] else "No active role"
        return (f"Your {name} role from {current['source'].lower()} does not allow {permission}. "
                f"Ask your {current['owner'].lower()} to review access. Account shows your current permissions; Permission requests lets you ask the policy owner for review.")
    except Exception:
        return "Your current access policy is unavailable. Ask an installation administrator to restore it before retrying."
