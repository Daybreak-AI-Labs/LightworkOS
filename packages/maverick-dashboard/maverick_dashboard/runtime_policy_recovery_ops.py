"""Protected full safety-settings review and actor-owned original outcomes."""
from __future__ import annotations

import json
import re
import secrets
import time
from urllib.parse import parse_qsl, urlsplit

from fastapi import HTTPException
from maverick import crypto_at_rest
from maverick import runtime_policy_recovery as core
from maverick.authority_effects import authority_effect_fence
from maverick.file_lock import cross_process_lock
from maverick.governed_operations import digest
from maverick.safety.secret_detector import scan

from . import auth, plain_labels, step_up, tools_ops_api
from .draft_api import context_for

PURPOSE = "lightwork.runtime-policy-restoration.v1"
TTL = 600
NOTICE = "This replaces only saved deployment safety settings for this installation. Backup and recovery must have been enabled before damage so native setting changes could retain trusted copies; it is off by default. No trusted copy means no restoration or reset from defaults. Installer and server settings still apply. It does not restore workspaces, user sign-in settings or external services. Protected connection credentials are also restored from the saved copy; their bytes stay hidden. Credentials must use protected connection fields; inline credential options or addresses cannot be safely reviewed here. The last 32 distinct policy copies are kept; copies need the original deployment encryption key."
LABELS = {"security": "Blocked capabilities", "denied_tools": "Capabilities blocked by these saved settings",
    "models": "AI choices", "model_rates": "Approved AI spending prices", "budget": "Work limits",
    "max_dollars": "Maximum task spending in USD", "task_limits_enabled": "Task limits apply",
    "plugins": "Extra capabilities", "enabled": "Enabled", "disabled": "Disabled", "access": "AI access",
    "allowed_models": "Permitted AI models", "styles": "Writing style", "active": "Chosen style",
    "mcp_servers": "Connected tools", "command": "Local connection program", "args": "Startup choices",
    "url": "Connection address", "env": "Protected connection values", "headers": "Protected connection headers",
    "auth_token": "Protected connection key", "oauth": "Protected sign-in details", "inherit_env": "Use installation connection values",
    "pin_sha256": "Verified connection identity", "input_per_mtok": "Input price per million units in USD",
    "output_per_mtok": "Output price per million units in USD", "source": "Price evidence", "as_of": "Evidence date",
    "valid_until": "Valid through", "approved_at": "Approved on", "approved_by": "Approved by"}
SECRET_FIELDS = frozenset({"env", "headers", "auth_token", "oauth"})
SECRET_OPTIONS = frozenset({"password", "passwd", "pass", "secret", "client-secret", "api-key", "apikey",
    "token", "access-token", "refresh-token", "auth-token", "authorization", "credential", "credentials", "signature"})


def _public(value, parent=""):
    """Refuse suspicious inline secrets instead of hiding consequential choices."""
    if isinstance(value, dict):
        for key, item in value.items():
            _public(key)
            if key not in SECRET_FIELDS:
                _public(item, key)
    elif isinstance(value, list):
        for item in value:
            _public(item, parent)
    elif isinstance(value, str):
        flag = value.split("=", 1)[0].lstrip("-").lower().replace("_", "-")
        address = urlsplit(value) if parent == "url" else None
        credential_address = address is not None and (address.username is not None or address.password is not None
            or any(key.lower().replace("_", "-") in SECRET_OPTIONS for key, _item in parse_qsl(address.query)))
        if scan(value) or credential_address or (parent == "args" and flag in SECRET_OPTIONS):
            raise core.PolicyRecoveryUnavailable("This copy has credential-like values outside protected connection fields. A complete safe review is unavailable; choose another trusted saved copy. No settings were restored or omitted from an approval.")


def authority(request, expected=None, *, write=False):
    auth.require_global_permission(request, "admin")
    current = digest([context_for(request), core.target(), auth.caller_role(request),
        sorted(auth.api_key_scopes(request)) if auth.api_key_scopes(request) is not None else None])
    if expected is not None and expected != current:
        raise HTTPException(409, "Your account, workspace or access changed. Reload Help before using private choices.")
    if write:
        tools_ops_api.same_origin(request)
        step_up.require_recent_mfa(request, "change_auth_settings")
        if not core.enabled():
            raise HTTPException(403, "Backup and recovery is disabled. Original request records remain available; no safety settings were restored.")
    return current


def _actor(request):
    return auth.caller_principal(request) or "local administrator"


def _policy(state):
    _public(state)
    def fields(value, parent=""):
        if isinstance(value, dict):
            result = []
            for key, item in sorted(value.items()):
                if parent == "models":
                    label = "Default AI" if key == "default" else plain_labels.agent_role_title(key)
                elif parent in {"mcp_servers", "model_rates"}:
                    label = key
                else:
                    label = LABELS.get(key)
                    if label is None:
                        raise core.PolicyRecoveryUnavailable("This copy contains a setting that this complete review cannot describe. Nothing was restored.")
                shown = "Present; restored from this saved policy, with credential bytes hidden" if key in SECRET_FIELDS and item else "Not present" if key in SECRET_FIELDS else fields(item, key)
                result.append({"label": label, "value": shown})
            return result
        if parent == "denied_tools":
            return [plain_labels.capability_label(item) for item in value]
        return value
    return fields(state)


def _current_policy(raw):
    if raw is None:
        return "No saved policy file is present. The complete saved copy below will become the deployment policy."
    try:
        return _policy(core.validated(raw.decode("utf-8")))
    except (UnicodeError, core.PolicyRecoveryUnavailable):
        return "Current saved safety settings cannot be completely shown safely. Their effective values are unavailable to this review. Their exact bytes will be preserved in encrypted custody before replacement; no defaults are substituted."


def catalog(request, offset=0, expected=None):
    current = authority(request, expected)
    with core.deployment():
        requests = core.store(requests=True).list(limit=core.MAX_REQUESTS + 1)
    if len(requests) > core.MAX_REQUESTS:
        raise core.PolicyRecoveryUnavailable("The retained request inventory exceeds its complete supported bound.")
    requests = sorted((row for row in requests if row.get("actor") == _actor(request)
        and row.get("owner") == context_for(request) and row.get("target") == core.target()),
        key=lambda row: (row["created_at"], row["id"]), reverse=True)
    rows = core.copies()
    binding, raw = core.source()
    authority(request, current)
    return {"context": current, "enabled": core.enabled(), "notice": NOTICE,
        "current": _current_policy(raw), "copies": [{"value": row["id"], "at": row["created_at"],
            "available": not row.get("_audit_pending")} for row in rows],
        "requests": [{"value": row["id"][4:], "at": row["created_at"]} for row in requests[offset:offset + 100]],
        "next_offset": offset + 100 if offset + 100 < len(requests) else None,
        "source_present": not binding["missing"]}


def review(request, snapshot, context):
    current = authority(request, context, write=True)
    with authority_effect_fence(), core.native._OVERRIDE_LOCK, cross_process_lock(core.native.overrides_path(), strict=True):
        authority(request, current, write=True)
        row, _text, state = core.retained(snapshot)
        before, raw = core.source()
        changes = {"before": _current_policy(raw), "after": _policy(state), "notice": NOTICE}
        if len(json.dumps(changes, ensure_ascii=False).encode()) > 262144:
            raise HTTPException(422, "This complete policy review is too large. Nothing was omitted or restored. Choose a smaller retained policy copy.")
        value = {"purpose": PURPOSE, "operation": secrets.token_hex(16), "nonce": secrets.token_hex(16),
            "actor": _actor(request), "owner": context_for(request), "context": current, "before": before,
            "snapshot": row["id"], "snapshot_revision": row["revision"], "snapshot_source": row["source_sha256"],
            "expires": time.time() + TTL}
        with core.deployment():
            token = crypto_at_rest.seal_to_str(json.dumps(value, separators=(",", ":")))
        if not crypto_at_rest.is_sealed_str(token):
            raise core.PolicyRecoveryUnavailable("The protected safety-settings review could not be encrypted.")
        authority(request, current, write=True)
        return {"context": current, "operation": value["operation"], "token": token,
            "changes": changes, "notice": NOTICE, "at": row["created_at"]}


def original(request, operation, context=None):
    current = authority(request, context)
    if not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(404, "Choose one of your original safety-settings restoration requests.")
    row = core.original(operation, _actor(request), context_for(request))
    confirmed = bool(row and row.get("state") == "confirmed" and not row.get("_audit_pending"))
    authority(request, current)
    return {"context": current, "confirmed": confirmed,
        "message": "Your original reviewed safety-settings restoration was recorded. Nothing was repeated. Current settings are independent and may have changed since then." if confirmed else
            "Your original restoration is unconfirmed. Nothing was repeated. Inspect the current safety settings and separately review a new decision if needed; a matching current file cannot confirm this original request.",
        "at": row.get("accepted_at") if confirmed else row.get("created_at") if row else None,
        "operation": operation, "notice": NOTICE}


def apply(request, token):
    current = authority(request)
    try:
        with core.deployment():
            if not crypto_at_rest.is_sealed_str(token):
                raise ValueError
            value = json.loads(crypto_at_rest.unseal_from_str(token))
            if not isinstance(value, dict):
                raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This protected review belongs to a different source or account. Read the original request or review current safety settings.") from exc
    if value.get("purpose") != PURPOSE or value.get("actor") != _actor(request) or value.get("owner") != context_for(request):
        raise HTTPException(409, "This protected review belongs to a different account or workspace. Nothing was restored.")
    authority(request, value["context"])
    def guard():
        with auth.fresh_configuration():
            authority(request, current, write=True)
    core.restore(value, actor=_actor(request), owner=context_for(request), guard=guard)
    return original(request, value["operation"], current)
