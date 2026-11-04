"""One reviewed native retired-workspace erasure; UI and Copilot share it."""
from __future__ import annotations

import json
import secrets
import time

from fastapi import HTTPException
from maverick import crypto_at_rest
from maverick.governed_operations import digest
from maverick.paths import maverick_home
from maverick.tenant import registry

from . import auth, step_up
from .draft_api import context_for

PURPOSE = "lightwork.workspace-erasure.v1"
TTL = 600


def access(request, expected=None, *, write=False):
    auth.require_global_permission(request, "admin")
    if write:
        step_up.require_recent_mfa(request, "delete_workspace")
    context = context_for(request)
    if expected is not None and expected != context:
        raise HTTPException(409, "Your account or workspace changed. Reopen Workspaces.")
    return context, auth._authorization_principal(request) or "local"


def call(function, *args, effect=False, **kwargs):
    try:
        return function(*args, **kwargs)
    except HTTPException:
        raise
    except PermissionError as exc:
        raise HTTPException(403, "This workspace erasure is not available to the current account.") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        message = ("The original erasure could not be confirmed. Records may already be erased. Check the original result; do not repeat it."
                   if effect else "Workspace recovery information is unavailable. No erasure was repeated. Read the available original results before another intentional attempt.")
        raise HTTPException(503, message) from exc


def inventory(request):
    context, _actor = access(request)
    rows = call(registry.list_removed_tenants)
    access(request, context)
    return {"context": context, "revision": digest(rows), "workspaces": rows}


def history(request, workspace):
    from maverick.authority_effects import authority_effect_fence
    context, actor = access(request)
    with authority_effect_fence():
        rows = call(registry.erasure_history, workspace, actor=actor, context=context,
                    effect_guard=lambda: access(request, context))
        access(request, context)
    return {"context": context, "originals": [public(row) for row in rows]}


def original_by_id(request, workspace, operation):
    from maverick.authority_effects import authority_effect_fence
    context, actor = access(request)
    with authority_effect_fence():
        row = call(registry.erasure_original, workspace, operation, actor=actor, context=context,
                   effect_guard=lambda: access(request, context))
        access(request, context)
    if row is None:
        raise HTTPException(404, "This original erasure is unavailable to the current account and workspace.")
    return public(row)


def _guard(request, material, *, write=False):
    access(request, material["context"], write=write)
    if material["home"] != str(maverick_home().resolve()):
        raise HTTPException(409, "The installation changed. Reopen Workspaces.")
    if write and time.time() >= material["expires_at"]:
        raise HTTPException(409, "This erasure review expired. Nothing further was erased. Check its original result and review the remaining records separately.")
    if write and _is_pinned_workspace(material["workspace"]):
        raise HTTPException(409, "This installation is fixed to that workspace. It cannot erase its own workspace here.")


def _is_pinned_workspace(workspace):
    """Whether ``workspace`` is the one this installation is bound to, by the
    same identity the registry uses (NFC, surrounding space ignored), whether
    the binding is ``MAVERICK_TENANT`` or ``[client] id``."""
    from maverick.paths import canonical_tenant_id, implicit_tenant_id
    pinned = implicit_tenant_id()
    if not pinned:
        return False
    try:
        return canonical_tenant_id(pinned.strip()) == canonical_tenant_id(str(workspace).strip())
    except ValueError:
        return pinned.strip() == str(workspace).strip()


def changes(value):
    from datetime import datetime, timezone
    removed = datetime.fromtimestamp(value["removed_at"], timezone.utc).strftime("%B %d, %Y at %H:%M:%S UTC")
    result = [
        {"label": "Workspace", "after": value["name"]},
        {"label": "Removed", "after": removed},
        {"label": "Records selected", "after": f"Every remaining local item in this removed workspace: {value['files']} files, {value['folders']} folders, {value['bytes']} bytes."},
        {"label": "What will happen", "after": "Permanently erase this workspace's local records, documents and local credentials. This cannot be undone or restored from Workspaces."},
        {"label": "What remains", "after": "The removed-workspace identity, deletion history and erasure results remain. Its old identity cannot be reused and former members do not regain access."},
        {"label": "Other copies", "after": "Backups, exported/downloaded files, provider records and other installations are outside this local erasure. Review their own retention controls separately."},
        {"label": "If interrupted", "after": "Some or all records may already be erased. Read this exact original result first. Another intentional cleanup requires a separate review of the current remaining records."},
        {"label": "Local work limit", "after": "The complete review includes up to 50,000 local items. Erasure runs for up to 15 seconds; any interruption remains unconfirmed and does not repeat automatically."},
    ]
    if value["previous_attempt"]:
        result.append({"label": "Earlier unconfirmed erasure", "after": "The earlier attempt remains unconfirmed and may have erased records. This is a new intentional cleanup of the records now remaining. It does not change the earlier result."})
    return result


def prepare(request, workspace, acknowledge_previous=False):
    from maverick.authority_effects import authority_effect_fence
    context, actor = access(request, write=True)
    material = {"purpose": PURPOSE, "workspace": workspace, "context": context, "actor": actor,
                "home": str(maverick_home().resolve()), "operation": secrets.token_hex(24),
                "expires_at": time.time() + TTL}
    with authority_effect_fence():
        value = call(registry.erasure_review, workspace,
                     effect_guard=lambda: _guard(request, material, write=True))
        if value["previous_attempt"] and acknowledge_previous is not True:
            raise HTTPException(409, "An earlier erasure is unconfirmed. Read the available results, then explicitly acknowledge that it may already have erased records before reviewing new cleanup.")
        material.update({"revision": value["revision"], "previous_attempt": value["previous_attempt"],
                         "changes": changes(value)})
        _guard(request, material, write=True)
        token = crypto_at_rest.seal_to_str(json.dumps(material, separators=(",", ":")))
        if not crypto_at_rest.is_sealed_str(token):
            raise HTTPException(503, "This complete review could not be retained securely. Nothing was erased.")
    return {"token": token, "operation": material["operation"], "context": context,
            "expires_at": material["expires_at"], "changes": material["changes"]}


def _open(token):
    try:
        # unseal_from_str hands back any text that is not sealed, so a typed-in
        # JSON object would otherwise pass for a review this server prepared.
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        keys = {"purpose", "workspace", "context", "actor", "home", "operation", "expires_at",
                "revision", "previous_attempt", "changes"}
        if not isinstance(value, dict) or set(value) != keys or value["purpose"] != PURPOSE:
            raise ValueError
        return value
    except Exception as exc:
        raise HTTPException(404, "This workspace erasure review is unavailable.") from exc


def public(row):
    return {"operation": row["operation"], "status": row["result"],
            "started_at": row["started_at"], "finished_at": row.get("finished_at"),
            "files": row["files"], "folders": row["folders"], "bytes": row["bytes"],
            "message": ("The selected local workspace records were erased. Backups and external copies were not erased."
                        if row["result"] == "confirmed" else
                        "This original erasure is unconfirmed. Some or all records may already be erased. It was not repeated.")}


def original(request, token):
    from maverick.authority_effects import authority_effect_fence
    material = _open(token)
    with authority_effect_fence():
        context, actor = access(request, material["context"])
        _guard(request, material)
        if actor != material["actor"]:
            raise HTTPException(404, "This original erasure is unavailable.")
        row = call(registry.erasure_original, material["workspace"], material["operation"], actor=actor,
                   context=context, effect_guard=lambda: _guard(request, material))
        _guard(request, material)
    return public(row) if row else {"status": "unconfirmed", "operation": material["operation"],
                                   "message": "No original erasure result is confirmed. Nothing was repeated. Review the current remaining records before another intentional attempt."}


def apply(request, token, confirmed):
    if confirmed is not True:
        raise HTTPException(400, "Confirm the complete irreversible erasure review first.")
    from maverick.authority_effects import authority_effect_fence
    material = _open(token)
    with authority_effect_fence():
        context, actor = access(request, material["context"], write=True)
        if actor != material["actor"]:
            raise HTTPException(404, "This erasure review belongs to another account.")
        # Original-only recovery remains usable after review expiry. No fresh
        # delete is dispatched merely because the present folder is absent.
        row = call(registry.erasure_original, material["workspace"], material["operation"], actor=actor,
                   context=context, effect_guard=lambda: _guard(request, material))
        if row is None:
            _guard(request, material, write=True)
            row = call(registry.erase_removed_tenant, material["workspace"], revision=material["revision"],
                       operation=material["operation"], actor=actor, context=context,
                       previous_attempt=material["previous_attempt"],
                       effect_guard=lambda: _guard(request, material, write=True), effect=True)
        _guard(request, material)
    return public(row)
