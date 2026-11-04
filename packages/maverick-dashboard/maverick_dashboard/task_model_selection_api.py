"""Plain task-local AI choices; never modifies installed model settings."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response
from maverick import task_model_selection as native

from . import auth
from .draft_api import context_for

router = APIRouter(tags=["chat"])


def choices(request):
    current_authority(request)
    from .provider_readiness import provider_labels, workspace_readiness
    labels = provider_labels()
    ready = {row["name"] for row in workspace_readiness()["providers"]
             if row["status"] in {"connected", "untested"}}
    try:
        values = native.catalog()
    except ValueError as exc:
        raise HTTPException(503, str(exc)) from exc
    return [{**row, "label": labels.get(row["provider"], row["provider"]) + " · " + row["label"]}
            for row in values if row["provider"] in ready]


def selection(request, model="", effort="", context="", *, request_identity=None):
    current_authority(request)
    if not model and not effort:
        return None
    if request_identity is not None and not request_identity.strip():
        raise HTTPException(422, "Keep one request identity for this AI choice and read its original admission before retrying.")
    if not isinstance(context, str) or not auth.constant_time_equals(context, context_for(request)):
        raise HTTPException(409, "Account or workspace changed. Refresh the AI choices before starting.")
    try:
        value = native.validate({"model": model, "effort": effort})
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    if value["model"] not in {row["value"] for row in choices(request)}:
        raise HTTPException(409, "This AI connection is not available. Check it in Providers or choose another model.")
    return value


def current_authority(request):
    from maverick.paths import current_tenant_id_strict

    from .api_flow_operator_review import _workspace_authority
    with auth.fresh_configuration():
        principal = getattr(request.state, "principal", None)
        via = (getattr(principal, "claims", None) or {}).get("via")
        refresh = {"session": auth._session_principal, "invite": auth._invite_session_principal,
                   "proxy": auth._proxy_principal}.get(via)
        if refresh is not None:
            fresh = refresh(request)
            if fresh is None or fresh.principal != principal.principal:
                raise HTTPException(401, "Sign in again before choosing how this task should run.")
            request.state.principal = principal = fresh
        if principal is not None:
            auth._enforce_scim_active(principal)
            auth._enforce_workspace_policies(request, principal)
        auth.require_permission(request, "operate")
        _workspace_authority(request, auth.caller_principal(request) or "", current_tenant_id_strict() or "")


def effect_guard(request, value, context):
    def guard():
        # Read current roles, session, SCIM and workspace, rather than trusting
        # claims captured before an upload or SQLite writer wait.
        selection(request, **value, context=context) if value is not None else current_authority(request)
    return guard


@router.get("/api/v1/chat/task-model-choices")
def read_choices(request: Request, response: Response):
    context = context_for(request)
    rows = choices(request)
    defaults = {"model": "", "effort": ""}
    principal = auth.caller_principal(request)
    from maverick import experience_preferences as preferences
    if principal and preferences.enabled():
        values = preferences.state(principal)["values"]
        defaults = {"model": values["chat_model"], "effort": values["chat_effort"]}
    current_authority(request)
    if context_for(request) != context:
        raise HTTPException(409, "Account or workspace changed while AI choices were read.")
    response.headers["Cache-Control"] = "private, no-store"
    return {"context": context, "models": rows, "personal_default": defaults,
            "notice": "This choice is for this task. Some specialists have their own AI settings. Workspace-approved backups, spending limits and required approvals still apply."}
