"""Reviewed access-key issuance with native metadata-only original outcomes."""
from __future__ import annotations

import math
import re
import time

from fastapi import HTTPException
from maverick import config
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.tenant import registry

from . import api_keys, api_keys_api, auth, tools_ops_api, workspace_tenants
from .draft_api import context_for

PAGE = "/account/api-keys#ak-requests"
TTL = 600
SCOPE_LABELS = {"tasks:read": "Read work", "tasks:write": "Run work", "approvals:decide": "Decide approvals",
                "audit:read": "Read activity records", "settings:write": "Change settings", "admin": "Full administrator access"}
NOTICE = "A new key is shown once in its original successful response. Its secret is never saved in request history or recovered. If that response is lost, read the original record, revoke the affected current key, then review a separate new key."


def authority(request, expected=None, *, write=False):
    auth.require_permission(request, "view")
    api_keys_api._require_non_key_caller(request)
    current = context_for(request)
    if expected is not None and current != expected:
        raise HTTPException(409, "Your account or workspace changed. Reload Access keys before continuing.")
    if write:
        tools_ops_api.same_origin(request)
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, "Current access settings are unavailable. No key was changed.")
    return current


def _material(request, body, data=None):
    actor = api_keys_api._caller(request)
    action = body["action"]
    data = api_keys._load() if data is None else data
    policy = api_keys.settings()
    if action != "revoke" and not policy["enabled"]:
        raise HTTPException(409, "Access keys are turned off. Original records remain readable; no new key can be issued.")
    if action == "create":
        owner = body.get("owner") or actor
        if owner != actor and (not api_keys_api._is_admin(request) or not api_keys.is_service_account_principal(owner)):
            raise HTTPException(403, "You can create keys for yourself; installation administrators can also choose a current service account.")
        label = api_keys._validate_label(body.get("label"))
        scopes = list(api_keys._validate_scopes(body.get("scopes"), owner))
        days = body.get("expires_in_days") or policy["default_days"]
        api_keys._expiry(days, time.time())
        workspace = api_keys._validate_workspace(body.get("workspace", ""), owner)
        key = None
    else:
        row = data["keys"].get(body.get("key_id"))
        if row is None or (row["owner"] != actor and not api_keys_api._is_admin(request)):
            raise HTTPException(404, "This current key is unavailable to your account.")
        key = {k: row[k] for k in ("id", "label", "owner", "scopes", "workspace", "created_at", "expires_at", "revoked_at", "grace_until", "replaced_by", "rotated_from")}
        if not api_keys._to_key(row).usable(time.time()) or (action == "rotate" and row["grace_until"] is not None):
            raise HTTPException(409, "This key's current state no longer supports this change. Read the latest key list.")
        owner, label, workspace = row["owner"], row["label"], row["workspace"]
        if action == "rotate":
            api_keys._validate_workspace(workspace, owner)
        scopes = [s for s in row["scopes"] if api_keys.SCOPES[s][0] in api_keys.owner_permissions(owner)]
        if action == "rotate" and not scopes:
            raise HTTPException(409, "The current owner no longer has permission for a replacement key.")
        days = min(max(1, int(round((row["expires_at"] - row["created_at"]) / 86400))), policy["max_days"])
    account = data["service_accounts"].get(owner.removeprefix("user:svc:")) if api_keys.is_service_account_principal(owner) else None
    if action != "revoke" and api_keys.is_service_account_principal(owner) and (account is None or account["disabled_at"] is not None):
        raise HTTPException(409, "This service account is no longer available for a new key.")
    workspace_name = "All workspaces the owner can access"
    if workspace:
        record = registry.get_tenant(workspace)
        if record is None and action != "revoke":
            raise HTTPException(409, "The selected workspace is no longer available.")
        workspace_name = record.display_name if record is not None else "Workspace no longer available"
    return {"actor": actor, "action": action, "owner": owner, "owner_permissions": sorted(api_keys.owner_permissions(owner)),
            "account": account, "label": label, "scopes": scopes, "workspace": workspace, "workspace_name": workspace_name,
            "days": days, "key": key, "policy": policy}


def prepare(request, body):
    context = authority(request, body["context"], write=True)
    try:
        material = _material(request, body)
    except api_keys.ApiKeyError as exc:
        message = str(exc)
        for key, label in SCOPE_LABELS.items():
            message = message.replace(key, label)
        raise HTTPException(422, message.replace("scope", "permission")) from exc
    authority(request, context, write=True)
    return {"context": context, "actor": material["actor"], "body": body, "source": digest(material), "expires": time.time() + TTL}, material


def review_rows(material):
    owner = "Your account" if material["owner"] == material["actor"] else "Service account: " + material["account"]["slug"] if material["account"] else "Another signed-in account"
    effect = {"create": "Issue one new key.", "rotate": "Issue one replacement key. The prior key remains usable only for the configured overlap period.",
              "revoke": "Stop this exact current key immediately. Programs using it will stop authenticating; it cannot be turned back on."}[material["action"]]
    return [{"label": "Change", "after": effect}, {"label": "Name", "after": material["label"]},
            {"label": "For", "after": owner}, {"label": "Permissions", "after": [SCOPE_LABELS[s] for s in material["scopes"]]},
            {"label": "Workspace", "after": material["workspace_name"]}, {"label": "Lifetime in days", "after": material["days"]},
            {"label": "Replacement overlap in hours", "after": material["policy"]["rotation_grace_hours"] if material["action"] == "rotate" else None},
            {"label": "One-time key and interruption", "after": NOTICE}]


def original(request, operation, *, prepared=None):
    context = authority(request)
    if not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(404, "This original key request is unavailable.")
    row = api_keys.issuance_original(operation)
    if row and (row["actor"] != api_keys_api._caller(request) or row["context"] != context):
        raise HTTPException(404, "This original request is unavailable to your account and workspace.")
    if row and prepared is not None and row["binding"] != digest(prepared):
        raise HTTPException(409, "This original request belongs to a different review.")
    result = {"context": context, "operation": operation, "confirmed": bool(row and row["state"] == "confirmed"), "notice": NOTICE,
              "message": "The original key change is unconfirmed. Nothing was issued or changed again. A matching current key is not an original receipt."}
    if row:
        result.update(action=row["action"], recorded_at=row["recorded_at"])
        if result["confirmed"]:
            result["message"] = "Your original reviewed key " + {"create": "creation", "rotate": "replacement", "revoke": "revocation"}[row["action"]] + " is confirmed. Nothing was repeated."
        key = api_keys.get_key(row["key_id"]) if row["key_id"] else None
        if key and (key.owner == api_keys_api._caller(request) or api_keys_api._is_admin(request)):
            result["current_key"] = key.to_public()
    authority(request, context)
    if result.get("current_key") and result["current_key"]["owner"] != api_keys_api._caller(request) and not api_keys_api._is_admin(request):
        result.pop("current_key")
    return result


def catalog(request):
    context = authority(request)
    state = api_keys_api._overview(request, request.query_params.get("all") in {"1", "true", "yes"})
    actor = api_keys_api._caller(request)
    rows = api_keys._load()["issuance_requests"]
    state.update(context=context, enabled=api_keys.enabled(), notice=NOTICE,
                 requests=[{"value": op, "label": row["action"].capitalize() + " / " + time.strftime("%b %d, %H:%M", time.localtime(row["recorded_at"]))}
                           for op, row in sorted(rows.items(), key=lambda pair: pair[1]["recorded_at"], reverse=True) if row["actor"] == actor and row["context"] == context],
                 workspaces=[{"value": t.id, "label": t.display_name or "Workspace"} for t in registry.list_tenants() if registry.is_active(t.id) and workspace_tenants.principal_can_select(actor, t.id)])
    authority(request, context)
    if state["admin"] and not api_keys_api._is_admin(request):
        raise HTTPException(403, "Your current administrator access changed. Reload Access keys before continuing.")
    return state


def apply(request, prepared, operation):
    context = authority(request, prepared["context"], write=True)
    with authority_effect_fence():
        if api_keys.issuance_original(operation) is not None:
            return original(request, operation, prepared=prepared)
        def guard(data):
            authority(request, context, write=True)
            if prepared["actor"] != api_keys_api._caller(request) or digest(_material(request, prepared["body"], data)) != prepared["source"]:
                raise HTTPException(409, "The current account, permission, key or policy changed. Review again; no key was changed.")
            authority(request, context, write=True)
            expires = prepared["expires"]
            if type(expires) not in {int, float} or not math.isfinite(expires) or not time.time() < expires <= time.time() + TTL:
                raise HTTPException(409, "This review expired. Review the current choices again; no key was changed.")
        body = prepared["body"]
        record = {"operation": operation, "actor": prepared["actor"], "context": context, "binding": digest(prepared), "action": body["action"]}
        try:
            if body["action"] == "create":
                key, secret = api_keys.create_key(label=body["label"], scopes=body["scopes"], owner=body.get("owner") or prepared["actor"],
                    created_by=prepared["actor"], expires_in_days=body.get("expires_in_days"), workspace=body.get("workspace", ""), reviewed_request=record, effect_guard=guard)
            elif body["action"] == "rotate":
                key, secret = api_keys.rotate_key(body["key_id"], actor=prepared["actor"], reviewed_request=record, effect_guard=guard)
            else:
                key = api_keys.revoke_key(body["key_id"], actor=prepared["actor"], reviewed_request=record, effect_guard=guard)
                secret = None
        except Exception:
            if api_keys.issuance_original(operation) is not None:
                return original(request, operation, prepared=prepared)
            raise
        result = original(request, operation, prepared=prepared)
        if secret is not None:
            result.update(secret=secret, key=key.to_public())
        return result
