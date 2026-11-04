"""People a page may offer as a choice: assignees and @mention targets.

Only named accounts whose current role in this workspace carries the
permission the object needs are offered, so a list never names someone who
could not open what it is about. The same check validates a choice when it is
saved, so a stale page cannot assign or notify someone who lost access.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)


def _role(principal: str, tenant: str | None, roles: dict[str, str]) -> str | None:
    from .auth import global_role_for_principal, is_dashboard_admin

    if is_dashboard_admin(principal):
        return "admin"
    if tenant:
        return roles.get(principal)
    return global_role_for_principal(principal)


def _known(tenant: str | None, roles: dict[str, str]) -> list[str]:
    from maverick.suite_grants import admin_principals

    known = [*roles, *sorted(admin_principals())]
    if not tenant:
        from .admin_pages import _signed_in_principals

        known += _signed_in_principals()
    return known


def _known_all(tenant: str | None, roles: dict[str, str]) -> set[str]:
    """Everyone :func:`_known` lists, without the 200-person cap on people
    who signed in (mapped as ``admin_pages._signed_in_principals`` does).
    Raises when the sign-in record cannot be read."""
    from maverick.suite_grants import admin_principals

    known = {*roles, *admin_principals()}
    if not tenant:
        from . import subject_directory

        subs = {str(entry.get("sub") or "").strip() for entry in subject_directory.load_index().values()}
        known |= {sub if sub.startswith("user:") else f"user:{sub}" for sub in subs if sub}
    return known


def _active_check():
    """``check(principal) -> bool``: not turned off in the company directory
    (SCIM), where such an account can no longer sign in. Unknown to the
    directory counts as active, as at sign-in. The directory is read once;
    an unreadable one raises, so nobody is offered."""
    from .scim_groups import active_check

    check = active_check()
    return lambda principal: check(principal) is not False


def _roster():
    from maverick.paths import current_tenant_id_strict

    from . import rbac

    tenant = current_tenant_id_strict()
    return tenant, (rbac.list_tenant_roles(tenant) if tenant else rbac.list_users())


def signed_in(principals) -> set[str]:
    """Those of ``principals`` the company directory has not turned off (see
    :func:`_active_check`). Not read for no principals; raises when it cannot
    be read."""
    principals = set(principals)
    if not principals:
        return set()
    active = _active_check()
    return {principal for principal in principals if active(principal)}


def allowed(principals, permission: str, *, known_only: bool = False) -> set[str]:
    """Those of ``principals`` who currently hold ``permission`` in this
    workspace (see :func:`may`). The roster is read once, and the company
    directory once and only if anyone holds the permission. ``known_only``:
    only people :func:`candidates` could list (on the roster, an
    administrator, or signed in before), not anyone a default role would
    cover. An unreadable source allows nobody (it raises inside
    ``strict_reads.strict()``)."""
    from . import rbac

    principals = {principal for principal in (str(p or "").strip() for p in principals)
                  if principal.startswith("user:")}
    if not principals:
        return set()
    try:
        tenant, roles = _roster()
        if known_only:
            principals &= _known_all(tenant, roles)
        holders = {principal for principal in principals
                   if permission in rbac.permissions_for(_role(principal, tenant, roles))}
        if not holders:
            return set()
        active = _active_check()
        return {principal for principal in holders if active(principal)}
    except Exception:  # noqa: BLE001 -- an unreadable roster offers nobody
        from . import strict_reads

        if strict_reads.active():
            raise
        log.warning("people directory unavailable", exc_info=True)
        return set()


def may(principal: str, permission: str) -> bool:
    """Whether ``principal`` currently holds ``permission`` in this workspace."""
    principal = str(principal or "").strip()
    return principal.startswith("user:") and principal in allowed({principal}, permission)


def candidates(permission: str, *, limit: int = 200) -> list[dict]:
    """``[{principal, label}]`` for everyone who holds ``permission`` now."""
    from . import rbac
    from .identity_format import humanize_principal

    try:
        tenant, roles = _roster()
        known = _known(tenant, roles)
        active = _active_check()
    except Exception:  # noqa: BLE001 -- an unreadable roster offers nobody
        log.warning("people directory unavailable", exc_info=True)
        return []
    out: dict[str, dict] = {}
    for principal in known:
        principal = str(principal or "").strip()
        if not principal.startswith("user:") or principal in out:
            continue
        if permission not in rbac.permissions_for(_role(principal, tenant, roles)) or not active(principal):
            continue
        ident = humanize_principal(principal)
        label = f"{ident.name} ({ident.detail})" if ident.detail and ident.detail != "Email" else ident.name
        out[principal] = {"principal": principal, "label": label}
        if len(out) >= limit:
            break
    return sorted(out.values(), key=lambda person: person["label"].lower())
