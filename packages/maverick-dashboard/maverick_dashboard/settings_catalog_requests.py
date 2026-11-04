"""Complete protected catalog review and actor-bound original save outcomes."""
from __future__ import annotations

import json
import math
import re
import secrets
import time

from fastapi import HTTPException
from maverick import config, crypto_at_rest
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.paths import current_tenant_id_strict

from . import auth, settings_store, step_up
from . import settings_all_page as native
from .api_flow_operator_review import _workspace_authority
from .draft_api import context_for

TTL = 600
PURPOSE = "lightwork.settings-catalog-request.v1"
NOTICE = "This records this person's original reviewed request, separately from current settings. A matching current value does not prove who saved it. Service restarts and any independent approvals remain separate."


def context(request):
    actor = auth.caller_principal(request) or "local administrator"
    tenant = current_tenant_id_strict() or ""
    suites, scopes = auth.caller_suites(request), auth.api_key_scopes(request)
    return digest([context_for(request), _workspace_authority(request, actor, tenant), auth.caller_role(request),
                   sorted(suites) if suites is not None else None, sorted(scopes) if scopes is not None else None])


def authority(request, expected=None, *, write=False):
    auth.require_global_permission(request, "admin")
    current = context(request)
    if expected is not None and expected != current:
        raise HTTPException(409, "Your account, workspace or access changed. Reload Settings before using private choices.")
    if write:
        native._app()._require_same_origin(request)
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, "Current configuration sources could not be checked. Your entered work is kept.")
    return current


def _store():
    return GovernedRecordStore("settings-catalog-requests", "SCR", "settings_catalog_request")


def _actor(request):
    return auth.caller_principal(request) or "local administrator"


def _plan(body):
    from . import settings_governance_level
    expanded, _learning = settings_governance_level.expand(body, native.SettingChange)
    writes, changes, _warnings, layers = native._plan(expanded)
    values = [[list(path), config._unseal_config_tree(value)] for path, value in sorted(writes.items())]
    return writes, changes, layers, digest(values)


def prepare(request, body, expected):
    from .settings_experience import review
    current = authority(request, expected, write=True)
    with settings_store._locked(strict=True):
        authority(request, current, write=True)
        plan = review(request, body)
        if plan.status_code != 200:
            return plan
        payload = json.loads(plan.body)
        if len(plan.body) > 262144:
            raise HTTPException(422, "This complete review is too large. Keep your draft and review fewer settings together.")
        _expanded, _changes, _layers, planned = _plan(body)
        operation = secrets.token_hex(16)
        value = {"purpose": PURPOSE, "operation": operation, "nonce": secrets.token_hex(16),
                 "actor": _actor(request), "context": current, "expires": time.time() + TTL,
                 "body": body.model_dump(mode="json"), "plan": planned}
        token = crypto_at_rest.seal_to_str(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
        if not crypto_at_rest.is_sealed_str(token) or len(token) > 1048576:
            raise HTTPException(422, "This complete protected review is too large. Review fewer settings together; nothing was saved.")
        authority(request, current, write=True)
        return {**payload, "context": current, "operation": operation, "token": token, "notice": NOTICE}


def _opened(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if value["purpose"] != PURPOSE or not re.fullmatch(r"[a-f0-9]{32}", value["operation"]):
            raise ValueError
        native.CatalogUpdate.model_validate(value["body"])
        return value
    except Exception as exc:
        raise HTTPException(409, "This protected review cannot be verified. Keep your draft and review current choices again.") from exc


def _owned(request, operation, expected, value=None):
    current = authority(request, expected)
    if not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(404, "This original settings request is unavailable.")
    selected = _store()
    row = selected.get("SCR-" + operation)
    if row and (row["actor"] != _actor(request) or row["owner"] != context_for(request)):
        raise HTTPException(404, "This original request belongs to another account or workspace.")
    if row and value is not None and row["nonce"] != value["nonce"]:
        raise HTTPException(409, "This original request belongs to a different protected review.")
    authority(request, current)
    if row and row.get("_audit_pending"):
        row = selected._flush(row)
        authority(request, current)
    return row


def original(request, operation, expected, *, value=None):
    current = authority(request, expected)
    row = _owned(request, operation, current, value)
    state = "audit_pending" if row and row.get("_audit_pending") else row["state"] if row else "unconfirmed"
    messages = {"confirmed": "Your original reviewed settings request was saved. Nothing was repeated.",
                "approval": "Your original request was submitted for independent approval. It did not save these settings.",
                "refused": "Your original request was refused. Keep your draft and review current settings before a new decision.",
                "audit_pending": "The original outcome is retained, but its activity record is not yet confirmed. Nothing was repeated. Read it again after activity recording is available."}
    result = {"operation": operation, "context": current, "confirmed": state == "confirmed", "state": state,
              "message": messages.get(state, "The original save is unconfirmed. Nothing was repeated. Inspect current settings before separately reviewing a new decision."),
              "notice": NOTICE, "settings": row.get("settings", []) if row else []}
    if row:
        result.update(recorded_at=row["updated_at"], restart=row.get("restart", False),
                      current="Current settings are checked separately below; later changes do not rewrite this original outcome.")
        if row.get("approval") is not None:
            result["approval"] = row["approval"]
    authority(request, current)
    return result


def catalog(request, expected=None, *, offset=0):
    current = authority(request, expected)
    retained = _store().list(limit=10001)
    if len(retained) > 10000:
        raise HTTPException(503, "The retained request list exceeds its supported bound. No original result was omitted; the list must be repaired before continuing.")
    rows = [row for row in retained if row["actor"] == _actor(request) and row["owner"] == context_for(request)]
    rows.sort(key=lambda row: (row["created_at"], row["id"]), reverse=True)
    authority(request, current)
    return {"context": current, "notice": NOTICE, "offset": offset, "total": len(rows),
            "next_offset": offset + 100 if offset + 100 < len(rows) else None,
            "requests": [{"value": row["id"][4:], "label": row["settings"][0]
            + (f" and {len(row['settings']) - 1} other settings" if len(row["settings"]) > 1 else "")
            + " / " + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))} for row in rows[offset:offset + 100]]}


def _fresh(request, value, body):
    authority(request, value["context"], write=True)
    expires = value.get("expires")
    if (_actor(request) != value["actor"] or type(expires) not in {int, float} or not math.isfinite(expires)
            or not time.time() < expires <= time.time() + TTL):
        raise HTTPException(409, "This settings review expired. Your draft is kept; review the current configuration again.")
    if native._revision() != body.expected_revision:
        raise HTTPException(409, "Configuration sources changed after your review. Your draft is kept; review current settings again.")


def _guard(request, value, body):
    _fresh(request, value, body)
    writes, changes, layers, planned = _plan(body)
    if planned != value["plan"]:
        raise HTTPException(409, "The available setting choices changed after review. Your draft is kept; review them again.")
    native._guard(request, writes, changes, layers)
    if any(c["setting"].section == "features"
           or c["setting"].id in native.settings_access_guard.SIGN_IN_IDS
           or c["setting"].id.startswith(native.settings_access_guard.SIGN_IN_PREFIXES)
           or c["setting"].id.startswith(native.settings_access_guard.KEY_PREFIXES) for c in changes):
        step_up.require_recent_mfa(request, "change_auth_settings")
    _fresh(request, value, body)


def apply(request, token, *, full=False):
    value = _opened(token)
    current = authority(request, write=True)
    body = native.CatalogUpdate.model_validate({**value["body"], "confirm": True})
    with settings_store._locked(strict=True):
        if _owned(request, value["operation"], current, value):
            return {"original": original(request, value["operation"], current, value=value)}, 200
        _guard(request, value, body)
        names = [native.catalog.BY_ID[item.id].label for item in body.changes]
        claim = _store().create({"id": "SCR-" + value["operation"], "actor": value["actor"], "context": current,
                "owner": context_for(request),
                "nonce": value["nonce"], "settings": names, "state": "started"},
                action="settings.catalog.started", actor=value["actor"], max_records=10000)
        if claim.get("_audit_pending"):
            raise HTTPException(503, "The original request record is unconfirmed. No settings save was attempted; read its original result.")
        try:
            response = native._catalog_update_locked(request, body, full, effect_guard=lambda: _guard(request, value, body))
            payload = json.loads(response.body)
            state = "approval" if response.status_code == 202 else "confirmed" if response.status_code == 200 else "refused"
            def finish(row):
                row.update(state=state, restart=bool(payload.get("restart")))
                if payload.get("quorum"):
                    row["approval"] = payload["quorum"]["approval_id"]
            _store().update(claim["id"], finish, expected_revision=claim["revision"],
                            action="settings.catalog.completed", actor=value["actor"])
            payload["original"] = original(request, value["operation"], current, value=value)
            return payload, response.status_code
        except Exception as exc:
            if isinstance(exc, HTTPException) and exc.status_code in {401, 403}:
                raise
            return {"original": original(request, value["operation"], current, value=value),
                    "message": "The original save could not be confirmed. Read its original result before a new reviewed decision."}, 503
