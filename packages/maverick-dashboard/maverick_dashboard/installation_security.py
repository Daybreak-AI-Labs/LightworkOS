"""Focused installation policy controls over the canonical settings writer.

No alternate authentication or sandbox implementation lives here. Reviews bind
all configuration sources; an interrupted admitted write is read, never rerun.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import secrets
import time
from dataclasses import asdict

from fastapi import HTTPException
from maverick import config, crypto_at_rest
from maverick.governed_records import GovernedRecordStore

from . import auth, settings_store, step_up
from . import settings_all_page as native
from . import settings_catalog as catalog
from .draft_api import context_for

PAGE = "/settings/security-installation"
PURPOSE = "lightwork.installation-security-review.v1"
TTL = 600
_CONTROLS = frozenset({"toggle", "select", "number", "text", "secret", "list", "multiselect"})


def revision(layers=None):
    # Mounted identity-provider secrets have higher precedence than saved
    # values but can change without any environment/config-file change.
    from maverick.oidc import load_oidc_config
    body = json.dumps([native._revision(layers), asdict(load_oidc_config())], sort_keys=True).encode()
    return hmac.new(crypto_at_rest._load_or_create_key(), b"installation-policy-source-v1\0" + body, hashlib.sha256).hexdigest()


def _deployment_secret(setting):
    if setting.id not in {"auth.oidc.client_secret", "auth.oidc.session_secret"}:
        return False
    from maverick.secret_provider import get_secret
    return bool(get_secret(setting.env[0]))


def settings():
    return tuple(s for s in catalog.SETTINGS if s.control in _CONTROLS and (
        s.section == "sandbox" or s.section == "containment" or s.section.startswith("auth.")
        or s.id == "security.network_policy"))


def authority(request):
    auth.require_global_permission(request, "admin")
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(409, "Installation settings are unavailable. No policy can change until configuration reading is restored.")
    return auth.caller_principal(request) or "local administrator"


def receipts():
    # One latest attempt per account/workspace; past decisions remain in audit.
    return GovernedRecordStore("installation-security-attempts", "ISC", "installation_security_attempt",
                               authority_scope="deployment_global")


def _identity(request):
    return "ISC-" + hashlib.sha256((authority(request) + ":" + context_for(request)).encode()).hexdigest()[:40]


def _rows(layers):
    result = []
    for setting in settings():
        row = native._row(setting, layers)
        present, _value = catalog.lookup(layers["tenant"], setting.path)
        if present:
            row.update(locked=True, value=None, value_text="Controlled by your workspace", source_text="Set by this workspace's installation policy")
        if _deployment_secret(setting):
            row.update(locked=True, value=None, value_text="Protected value supplied", source_text="Set by your server's secret service")
        result.append({key: row[key] for key in ("id", "label", "help", "control", "choices", "minimum", "maximum", "step",
            "unit", "value", "value_text", "locked", "source_text", "max_length", "subgroup", "optional")})
    return result


def state(request):
    authority(request)
    layers = native._sources()
    rows = _rows(layers)
    from maverick.oidc import load_oidc_config, login_enabled
    from maverick.sandbox import container_backend_required

    from .saml import load_saml_config, saml_enabled
    oidc, saml = load_oidc_config(), load_saml_config()
    work = config.get_sandbox()
    last = receipts().get(_identity(request))
    return {"revision": revision(layers), "context": context_for(request), "rows": rows, "checked_at": time.time(),
        "latest_attempt": {"operation": last["operation"], "status": "unconfirmed" if last.get("_audit_pending") else last["status"], "policy": last["label"]} if last else None,
        "summary": {"work_area": str(work["backend"]), "container_required": container_backend_required(),
            "company_signin": oidc.enabled, "company_login_configured": login_enabled(oidc),
            "company_login_support": importlib.util.find_spec("jwt") is not None,
            "single_signon_configured": saml_enabled(saml), "single_signon_support": importlib.util.find_spec("saml2") is not None},
        "notice": "These are current settings, not proof of a successful sign-in or isolation test. Existing tasks keep the work area they already started. New work uses current policy; stronger deployment and workspace controls remain authoritative."}


def _change(request, setting_id, value, reviewed_revision, *, inherit=False):
    authority(request)
    available = {s.id: s for s in settings()}
    setting = available.get(setting_id)
    if setting is None:
        raise HTTPException(422, "Choose an available installation policy.")
    layers = native._sources()
    if reviewed_revision != revision(layers):
        raise HTTPException(409, "Settings or their controlling source changed. Review the current policy again.")
    if catalog.lookup(layers["tenant"], setting.path)[0]:
        raise HTTPException(409, "This policy is fixed by your workspace. A hidden installation value will not be saved.")
    if _deployment_secret(setting):
        raise HTTPException(409, "This protected value is supplied by your server's secret service. A hidden replacement will not be saved.")
    body = native.CatalogUpdate(expected_revision=native._revision(layers),
        changes=[native.SettingChange(id=setting_id, value=value, inherit=inherit)], confirm=True)
    try:
        writes, changes, weakening, layers = native._plan(body)
        if setting.section.startswith("auth."):
            step_up.require_recent_mfa(request, "change_auth_settings")
        access = native._guard(request, writes, changes, layers) if changes else []
    except native._Refused as exc:
        raise HTTPException(exc.status, exc.message) from exc
    except native.settings_access_guard.Refused as exc:
        raise HTTPException(409, exc.message) from exc
    rows = [{"label": change["setting"].label,
             "before": catalog.display_value(change["setting"], change["old"]),
             "after": catalog.display_value(change["setting"], change["new"])} for change in changes]
    warnings = [item["warning"] for item in weakening + access]
    return body, rows, warnings


def review(request, setting_id, value, reviewed_revision, *, inherit=False):
    body, changes, warnings = _change(request, setting_id, value, reviewed_revision, inherit=inherit)
    # Secret material stays sealed and is never sent to Copilot or saved as a draft.
    material = {"purpose": PURPOSE, "owner": authority(request), "context": context_for(request),
        "revision": reviewed_revision, "change": body.changes[0].model_dump(), "operation": secrets.token_hex(16),
        "expires": time.time() + TTL}
    serialized = json.dumps(material, sort_keys=True, allow_nan=False)
    if len(serialized.encode()) > 8500:
        raise HTTPException(422, "This policy list is too long for a protected quick review. Open its complete control in All settings; nothing changed.")
    token = crypto_at_rest.seal_to_str(serialized)
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "This review could not be protected. Nothing changed.")
    if reviewed_revision != revision() or context_for(request) != material["context"]:
        raise HTTPException(409, "The policy changed during review. Review the current values again.")
    return {"token": token, "operation": material["operation"], "context": material["context"], "changes": changes,
            "warnings": warnings, "message": "Apply only this reviewed policy using the installation's existing access, approval and activity checks."}


def _open(request, token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        material = json.loads(crypto_at_rest.unseal_from_str(token))
        if (set(material) != {"purpose", "owner", "context", "revision", "change", "operation", "expires"}
                or material["purpose"] != PURPOSE or material["owner"] != authority(request)
                or material["context"] != context_for(request) or not time.time() < material["expires"] <= time.time() + TTL):
            raise ValueError
        return material
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(409, "This review expired or your account changed. Start a new review.") from exc


def readback(request, operation):
    actor = authority(request)
    row = receipts().get(_identity(request))
    if not row or row.get("owner") != actor or row.get("context") != context_for(request):
        return {"status": "not_found", "message": "No saved attempt matches this original operation. Refresh current policy before preparing another review."}
    if row.get("operation") != operation:
        historical = next((item for item in row.get("recent_attempts", []) if item.get("operation") == operation), None)
        if not historical:
            return {"status": "not_found", "message": "This earlier attempt is no longer in recent readback. Its activity history remains retained. Read current policy before preparing a new change."}
        row = {**historical, "_audit_pending": row.get("_audit_pending")}
    pending = bool(row.get("_audit_pending"))
    status = "unconfirmed" if pending or row["status"] in {"applying", "unknown"} else row["status"]
    return {"status": status, "message": row.get("message") if status != "unconfirmed" else
        "The original attempt may have changed policy. Read current settings and Activity before preparing a new review. This attempt will not run again.",
        "operation": operation, "policy": row["label"], "checked_at": time.time()}


def apply(request, token, *, confirmed):
    if confirmed is not True:
        raise HTTPException(422, "Confirm the exact reviewed change.")
    material = _open(request, token)
    return apply_change(request, material["change"], material["revision"], material["operation"])


def apply_change(request, change, reviewed_revision, operation):
    actor, context, identifier = authority(request), context_for(request), _identity(request)
    # Same lock as the canonical writer: source validation and policy write
    # cannot race another local installation-settings writer.
    with settings_store._locked(strict=True):
        store = receipts()
        previous = store.get(identifier)
        if previous and (previous.get("operation") == operation or any(item.get("operation") == operation for item in previous.get("recent_attempts", []))):
            return readback(request, operation)
        if previous and (previous.get("_audit_pending") or previous.get("status") in {"applying", "unknown"}):
            raise HTTPException(409, "An earlier attempt needs review. Read its result and current policy here before allowing a new change.")
        body, _changes, _warnings = _change(request, change["id"], change.get("value"), reviewed_revision, inherit=change.get("inherit", False))
        label = catalog.BY_ID[change["id"]].label
        recent = [item for item in (previous or {}).get("recent_attempts", []) if item["started"] >= time.time() - TTL * 2]
        if previous:
            recent.append({key: previous[key] for key in ("operation", "status", "label", "started", "message") if key in previous})
        if len(recent) >= 64:
            raise HTTPException(429, "Many installation changes were reviewed recently. Wait 20 minutes before another change; saved policy and activity history remain intact.")
        def begin(row):
            for key in ("message", "resulting_revision"):
                row.pop(key, None)
            row.update(owner=actor, context=context, operation=operation, source_revision=reviewed_revision, label=label, status="applying", started=time.time(), recent_attempts=recent)
        if previous:
            row = store.update(identifier, begin, expected_revision=previous["revision"], actor=actor, action="installation_policy_attempt_started")
        else:
            initial = {"id": identifier}
            begin(initial)
            row = store.create(initial, actor=actor, action="installation_policy_attempt_started")
        if row.get("_audit_pending"):
            raise HTTPException(503, "The attempt receipt is waiting for Activity. Policy was not changed; read this saved attempt before continuing.")
        # Receipt admission can take time. Check mounted credentials again
        # immediately before the canonical write, in the same writer lock.
        if revision() != reviewed_revision:
            store.update(identifier, lambda record: record.update(status="refused", message="The controlling source changed before the write. Nothing was applied; review current policy again."),
                         expected_revision=row["revision"], actor=actor, action="installation_policy_source_changed")
            return readback(request, operation)
        try:
            response = native._catalog_update_locked(request, body)
            result = json.loads(response.body)
            if response.status_code == 202:
                status, message = "queued", result.get("message", "The change is waiting in Approvals. Policy has not changed.")
            elif response.status_code >= 400:
                status, message = "refused", result.get("message", result.get("detail", "The installation refused this change."))
            else:
                status = "confirmed"
                message = ("The installation saved the reviewed policy and recorded its settings change. Read current values below."
                           if result.get("changed") else "The policy already matched this review. No policy write was needed; this review's outcome is recorded.")
        except Exception:
            status, message = "unknown", "The original attempt could not be confirmed. Read current policy and Activity; no write will be repeated."
        def finish(record):
            record.update(status=status, message=message, resulting_revision=revision())
        store.update(identifier, finish, expected_revision=row["revision"], actor=actor, action="installation_policy_attempt_result")
        return readback(request, operation)


def acknowledge(request, operation):
    """Close uncertainty by recording review, never by asserting success."""
    actor = authority(request)
    with settings_store._locked(strict=True):
        store, identifier = receipts(), _identity(request)
        row = store.get(identifier)
        if not row or row.get("operation") != operation or row.get("context") != context_for(request):
            raise HTTPException(409, "Choose the saved original attempt for this account.")
        if row.get("_audit_pending"):
            # Flush only the existing outbox; no policy effect is repeated.
            row = store.update(identifier, lambda _row: None, expected_revision=row["revision"],
                               actor=actor, action="installation_policy_receipt_retry")
        if row.get("_audit_pending"):
            raise HTTPException(503, "Activity is still unavailable. The original receipt is retained; no policy write was repeated.")
        if row["status"] in {"unknown", "applying"}:
            store.update(identifier, lambda record: record.update(status="reviewed_unknown", message="An administrator reviewed this uncertain attempt. Its success remains unverified; a new change needs a fresh current-policy review."),
                         expected_revision=row["revision"], actor=actor, action="installation_policy_uncertainty_reviewed")
        return readback(request, operation)


def work_area_readiness(request):
    authority(request)
    if not native._check_allowed():
        raise HTTPException(429, "Wait a minute before checking again.")
    from .api import _probe_container_daemon
    backend = str(config.get_sandbox()["backend"]).lower()
    if backend == "local":
        return {"ok": False, "message": "Commands are configured to run directly on this computer. This is not an isolated work area; deployment rules may refuse it or choose a required container instead."}
    if backend in {"docker", "podman", "gvisor"}:
        probe = _probe_container_daemon("docker" if backend == "gvisor" else backend)
        if not probe["available"]:
            return {"ok": False, "message": "The selected work area did not answer. Open its desktop application and use Check again; Lightwork will keep the saved policy."}
        if backend == "gvisor":
            try:
                from maverick.sandbox.gvisor import validate_docker_gvisor_runtime
                validate_docker_gvisor_runtime((config.load_config().get("sandbox") or {}).get("runtime"))
            except Exception:
                return {"ok": False, "message": "The selected stronger isolation program could not be verified. Commands stay subject to the existing refusal rules."}
        return {"ok": True, "message": "The selected container service answered. This connection check did not run a customer command or prove complete isolation; each task still passes its native policy checks."}
    return {"ok": False, "message": "This remote or specialist work area is configured. Its live connection is not verified by this page; successful task execution remains unverified. No fallback to direct server commands was enabled."}


def check(request, kind):
    authority(request)
    if kind == "work-area":
        return work_area_readiness(request)
    if not native._check_allowed():
        raise HTTPException(429, "Wait a minute before checking again.")
    key = "auth.oidc.issuer" if kind == "company-signin" else "auth.saml.idp_metadata_url"
    result = native._run_check(catalog.BY_ID[key], None)
    return {"ok": result.ok, "message": result.message}
