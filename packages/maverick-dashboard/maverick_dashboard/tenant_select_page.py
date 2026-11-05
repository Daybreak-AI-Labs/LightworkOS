"""Workspace tenant picker: choose the tenant every workbench runs as.

Dozens of tenant-scoped workbenches refuse to run unbound (their APIs 409
with "select an active tenant ..."). Besides the ``MAVERICK_TENANT``
environment variable or an enterprise client binding -- both
config-file/environment steps -- this page is the in-app path: it lists
the registry's tenants, lets an admin pick (or create) one, and the
``bind_active_tenant`` middleware scopes every later request to it.

Rendering filters the roster to the caller's memberships. Global tenant
administrators may see/create every tenant; ordinary members may switch only
among their own workspaces.
"""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from maverick.billing import SELF_HOSTED_PLAN

PAGE_PATH = "/workspace/tenant"

# The workspace the picker's one-click action creates; the same record is
# provisioned automatically for the first signed-in administrator (below).
# It is the installation's own workspace, so no billing plan gates it.
FIRST_WORKSPACE = {"id": "local", "display_name": "My workspace", "plan": SELF_HOSTED_PLAN}


def _safe_return_path(value: str | None) -> str:
    """Return a same-origin browser destination or an empty fallback.

    A leading backslash can be normalized into a protocol-relative URL by a
    browser, so the usual single-leading-slash check is not sufficient on its
    own.  Keep this boundary aligned with the login redirect guards.
    """
    if not isinstance(value, str) or not value or len(value) > 2048:
        return ""
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        return ""
    if not all(ord(char) >= 0x20 and char != "\x7f" for char in value):
        return ""
    return value


def _page_context(
    request: Request,
    detail: str = "",
    *,
    return_to: str = "",
) -> dict:
    import os

    from maverick.tenant.registry import list_tenants

    from maverick_dashboard import settings_store, workspace_tenants

    from .auth import caller_principal, has_global_permission

    principal = caller_principal(request)
    visible_ids: frozenset[str] | None = None
    if principal:
        try:
            visible_ids = workspace_tenants.accessible_tenant_ids(principal)
        except workspace_tenants.WorkspaceTenantStoreError:
            visible_ids = frozenset()

    try:
        tenants = [
            {
                "id": rec.id,
                "name": getattr(rec, "display_name", "") or rec.id,
                "plan": getattr(rec, "plan", ""),
                "active": bool(rec.active),
            }
            for rec in list_tenants()
            if visible_ids is None or rec.id in visible_ids
        ]
    except Exception:
        # A corrupt roster must not turn the picker into a 500: the page is
        # how an operator digs out of exactly this kind of state.
        tenants = []
    from .workspace_display import duplicate_workspace_ids

    duplicates = duplicate_workspace_ids((tenant["id"], tenant["name"]) for tenant in tenants)
    for tenant in tenants:
        tenant["reference"] = tenant["id"] if tenant["id"] in duplicates else ""
    selected = (
        workspace_tenants.get_selection(principal)
        if principal
        else settings_store.active_tenant()
    )
    is_admin = has_global_permission(request, "admin")
    return {
        "detail": detail,
        "tenants": tenants,
        "selected": selected,
        "env_tenant": os.environ.get("MAVERICK_TENANT", "").strip(),
        "is_admin": is_admin,
        "can_select": not os.environ.get("MAVERICK_TENANT", "").strip() and (not principal or is_admin or bool(tenants)),
        "membership_filtered": principal is not None and not is_admin,
        "return_to": _safe_return_path(return_to),
    }


def provision_first_workspace(principal: str) -> str | None:
    """Create the first workspace and select it for ``principal``.

    Mirrors exactly what the picker's one-click button does (create ``local``
    through the registry, record the global audit event, select it for this
    principal) and returns the new workspace id. Anything else -- no
    principal, a MAVERICK_TENANT or client binding, an existing roster, a
    registry or audit refusal -- returns None and provisions nothing. The
    caller decides who may provision.
    """
    import os

    from maverick.paths import current_tenant_id
    from maverick.tenant.registry import create_tenant, delete_tenant, list_tenants

    from maverick_dashboard import workspace_tenants

    if not principal or os.environ.get("MAVERICK_TENANT", "").strip():
        return None
    try:
        if current_tenant_id() is not None:
            return None
        if list_tenants():
            return None
        rec = create_tenant(
            FIRST_WORKSPACE["id"],
            plan=FIRST_WORKSPACE["plan"],
            display_name=FIRST_WORKSPACE["display_name"],
            allocate_suffix=True,
        )
    except Exception:
        return None
    from maverick.audit import AuditRefused, EventKind, audit_event

    try:
        audit_event(
            EventKind.TENANT_CREATED,
            agent=principal,
            _global=True,
            actor=principal,
            tenant=rec.id,
            plan=rec.plan,
            max_daily_dollars=rec.max_daily_dollars,
        )
    except AuditRefused:
        try:
            delete_tenant(rec.id, purge=False)
        except Exception:  # pragma: no cover -- the picker still renders
            pass
        return None
    try:
        workspace_tenants.set_selection(principal, rec.id)
    except Exception:
        return None
    return rec.id


def first_workspace_for_admin(request: Request) -> RedirectResponse | None:
    """Provision and select the first workspace for a signed-in global
    administrator who reaches a tenant gate on an installation with no
    workspace at all, then send them back to the page that refused.

    The owner's account is the demo account: it must never land on a "no
    workspaces exist yet" dead end that a one-click button would resolve
    anyway. A local owner already gets this workspace when the claim
    completes (:mod:`local_owner`); this covers administrators who arrive
    another way. Anything else -- auth off, a non-admin, or whatever
    :func:`provision_first_workspace` declines -- returns None and the picker
    renders as before.
    """
    from .auth import caller_principal, has_global_permission

    principal = caller_principal(request)
    if not principal or not has_global_permission(request, "admin"):
        return None
    if provision_first_workspace(principal) is None:
        return None
    back = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    return RedirectResponse(_safe_return_path(back) or PAGE_PATH, status_code=303)


def tenant_select_response(
    request: Request,
    templates: Jinja2Templates,
    *,
    detail: str = "",
) -> HTMLResponse:
    """The picker rendered in place of a tenant-gate 409 (keeps the URL, so
    selecting a tenant and reloading lands on the workbench that refused).
    A signed-in administrator on an empty installation skips the picker: the
    first workspace is created and selected for them."""
    provisioned = first_workspace_for_admin(request)
    if provisioned is not None:
        return provisioned
    return templates.TemplateResponse(
        request,
        "tenant_select.html",
        _page_context(
            request,
            detail,
            return_to=request.url.path
            + (f"?{request.url.query}" if request.url.query else ""),
        ),
        status_code=409,
    )


def create_tenant_select_page_router(templates: Jinja2Templates) -> APIRouter:
    if not isinstance(templates, Jinja2Templates):
        raise TypeError("tenant picker requires Jinja templates")
    router = APIRouter(tags=["workspace-tenant"])

    @router.get(PAGE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def workspace_tenant(request: Request) -> HTMLResponse:
        from .auth import require_workspace_picker_access

        require_workspace_picker_access(request)
        return templates.TemplateResponse(
            request,
            "tenant_select.html",
            _page_context(request, return_to=request.query_params.get("next", "")),
        )

    return router
