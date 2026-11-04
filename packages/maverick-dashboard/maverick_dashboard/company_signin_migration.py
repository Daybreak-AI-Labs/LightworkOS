"""Reviewed local-owner migration and narrowly retained OIDC recovery."""
from __future__ import annotations

import json
import math
import re
import secrets
import time
from contextlib import contextmanager
from urllib.parse import urlparse

from fastapi import HTTPException
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.paths import reset_tenant, set_tenant

from . import auth, company_signin_tests, local_owner, rbac, settings_store, step_up
from . import settings_all_page as native
from .draft_api import context_for

TTL = 600
MAX_RECORDS = 1000
PURPOSE = "lightwork.company-signin-migration.v1"
SETTING = "auth.oidc.enabled"
ACTIVATION_FLOW = "company-signin-activation"  # the owner's activation review (passphrase and code)
RECOVERY_FLOW = "company-signin-recovery"  # the restricted recovery form (passphrase and code)
NOTICE = ("Company sign-in replaces local passphrase sign-in. It does not give anyone a role. "
          "The verified company account must already have installation administrator access. "
          "On this computer, the original owner can separately review restoring only the previous "
          "company-sign-in choice. This recovery cannot change company proxy, enterprise, second-factor "
          "or user-role policy, and never opens a dashboard session while company sign-in is active.")


@contextmanager
def deployment():
    token = set_tenant(None)
    try:
        with crypto_at_rest.deployment_key_scope():
            yield
    finally:
        reset_tenant(token)


def store():
    return GovernedRecordStore("company-signin-migrations", "CSM", "company_signin_migration",
                               authority_scope="deployment_global")


def recovery_page_allowed(request):
    """Allow only the generic loopback form, without returning owner metadata."""
    local_owner._local(request)


def _claim_binding(row):
    return digest([row["email"], row["salt"], row["password_hash"], row["status"], row["created_at"]])


def _owner():
    row = local_owner._read()
    if not row or row["status"] != "ready":
        raise HTTPException(409, "Complete this computer's owner setup before changing its sign-in method.")
    principal = "user:" + row["email"]
    role = rbac.get_stored_role(principal)
    if role is None or "admin" not in rbac.permissions_for(role):
        raise HTTPException(403, "The original owner's current role cannot manage installation sign-in.")
    from maverick.oidc import VerifiedPrincipal
    auth._enforce_scim_active(VerifiedPrincipal(sub=row["email"], issuer="invite-session", audience="", claims={}))
    return row


def _policy(request=None):
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Current sign-in policy cannot be read. No sign-in choice was changed.")
    cfg = config.load_config()
    access = native.settings_access_guard.access_for(cfg)
    if access.token_env or access.proxy or access.saml_policy or access.client_enforced:
        raise HTTPException(403, "This installation's managed policy does not permit local-owner sign-in migration or recovery.")
    from .mfa_policy import require_mfa
    if require_mfa():
        raise HTTPException(403, "The current second-factor policy does not permit recovery using only an owner passphrase.")
    if request is not None:
        from .ip_allowlist import BLOCKED_MESSAGE, installation_allows, workspace_allows
        if not installation_allows(request) or not workspace_allows(request):
            raise HTTPException(403, BLOCKED_MESSAGE)
    return cfg


def authority(request, expected=None):
    local_owner._local(request)
    current = company_signin_tests.authority(request, expected)
    row = _owner()
    if auth.caller_principal(request) != "user:" + row["email"]:
        raise HTTPException(403, "Open this setup using this computer's original owner account.")
    _policy(request)
    return current, row


def _proof(request, selected):
    row = company_signin_tests.STORE.get(selected)
    if not row or row.get("_audit_pending") or row.get("actor") != auth.caller_principal(request) or row.get("owner") != context_for(request):
        raise HTTPException(404, "Choose one of your verified company sign-ins.")
    checked = row.get("checked_at")
    if type(checked) not in {int, float} or not math.isfinite(checked) or not 0 <= time.time() - checked < TTL:
        raise HTTPException(409, "Try company sign-in again before enabling it. This check is no longer current.")
    if row["configuration"] != company_signin_tests.configuration_key(company_signin_tests.current_configuration()):
        raise HTTPException(409, "The provider details changed after this sign-in. Try the current sign-in again.")
    principal = "user:" + row["account"]
    from maverick.oidc import VerifiedPrincipal
    auth._enforce_scim_active(VerifiedPrincipal(sub=row["account"], issuer=row["provider"], audience="", claims={}))
    from maverick.suite_grants import admin_principals
    role = rbac.get_stored_role(principal)
    if principal not in admin_principals() and (role is None or "admin" not in rbac.permissions_for(role)):
        raise HTTPException(409, "Give this verified company account installation administrator access on People, then review activation again. No role was granted here.")
    return row


def _choice():
    layers = native._sources()
    setting = native.catalog.BY_ID[SETTING]
    if native.catalog.lookup(layers["tenant"], setting.path)[0]:
        raise HTTPException(409, "Workspace policy controls this sign-in choice. Open installation setup without that workspace policy before migrating sign-in.")
    state = native._resolve(setting, layers)
    if state["locked"] or not state["known"]:
        raise HTTPException(409, "Installer or server policy controls company sign-in. This page cannot replace that policy.")
    present, value = native._layer_value(setting, layers["here"])
    from maverick.config_resets import is_reset
    return layers, state, {"present": present, "value": value if present else None, "reset": is_reset(layers["here"], setting)}


def _records():
    with deployment():
        rows = store().list(limit=MAX_RECORDS + 1)
    if len(rows) > MAX_RECORDS:
        raise HTTPException(503, "The retained sign-in request list exceeds its supported bound. No requests were silently omitted.")
    return sorted(rows, key=lambda row: (row["created_at"], row["id"]), reverse=True)


def catalog(request):
    current, owner = authority(request)
    checks = company_signin_tests.STORE.list(limit=101)
    if len(checks) > 100:
        raise HTTPException(503, "The retained sign-in checks exceed this view's supported bound.")
    key = company_signin_tests.configuration_key(company_signin_tests.current_configuration())
    checks = [row for row in checks if row.get("actor") == auth.caller_principal(request)
              and row.get("owner") == context_for(request) and row.get("configuration") == key and not row.get("_audit_pending")]
    def label(row):
        return row.get("account_label", "Verified company account") + " / " + time.strftime("%b %d, %H:%M", time.localtime(row["checked_at"]))
    requests = [row for row in _records() if row["actor"] == auth.caller_principal(request)
                and row["owner_claim"] == _claim_binding(owner)]
    authority(request, current)
    return {"context": current, "notice": NOTICE, "checks": [{"value": row["id"], "label": label(row)} for row in checks],
            "requests": [{"value": row["id"][4:], "label": ("Restore previous sign-in" if row["kind"] == "recovery" else "Enable company sign-in")
                          + " / " + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))} for row in requests]}


def preset(request, provider, directory, application, expected):
    """Return documented nonsecret defaults; never contact or save a provider."""
    current, _owner_value = authority(request, expected)
    if provider == "microsoft":
        if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", directory):
            raise HTTPException(422, "Enter the Directory ID shown in your Microsoft app registration.")
        issuer = "https://login.microsoftonline.com/" + directory.lower() + "/v2.0"
    elif provider == "google":
        issuer = "https://accounts.google.com"
    elif provider == "okta":
        address = urlparse(directory)
        if (address.scheme != "https" or not address.hostname or address.netloc != address.hostname
                or address.path not in {"", "/"} or address.query or address.fragment):
            raise HTTPException(422, "Enter your Okta organization's HTTPS address without a path, port or sign-in details.")
        issuer = "https://" + address.hostname
    else:
        raise HTTPException(422, "Choose a supported provider preset or use the existing provider fields.")
    values = {"issuer": issuer, "client_id": application, "audience": application,
              "redirect_uri": str(request.base_url).rstrip("/") + "/auth/callback",
              "authorization_endpoint": "", "token_endpoint": "", "jwks_uri": "", "end_session_endpoint": ""}
    try:
        values = {"auth.oidc." + name: native.catalog.coerce(native.catalog.BY_ID["auth.oidc." + name], value) if value else ""
                  for name, value in values.items()}
    except native.catalog.SettingError as exc:
        raise HTTPException(422, "Check the application name and this site's registered return address.") from exc
    authority(request, current)
    return {"context": current, "values": values, "notice": "These are unsaved provider details. Existing entered work is kept. Supply the provider's application password and a session key separately, then use the complete Settings review and real sign-in check. No provider was contacted or enabled."}


def _seal(value):
    with deployment():
        token = crypto_at_rest.seal_to_str(json.dumps(value, separators=(",", ":"), allow_nan=False))
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "The protected sign-in review could not be retained. Nothing was changed.")
    return token


def _opened(token):
    try:
        with deployment():
            value = json.loads(crypto_at_rest.unseal_from_str(token))
        if value["purpose"] != PURPOSE or not re.fullmatch(r"[a-f0-9]{32}", value["operation"]) or value["kind"] not in {"activation", "recovery"}:
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(409, "This sign-in review cannot be verified. Review the current choices again.") from exc


def _deadline(value):
    expires = value.get("expires")
    if type(expires) not in {int, float} or not math.isfinite(expires) or not time.time() < expires <= time.time() + TTL:
        raise HTTPException(409, "This sign-in review expired. Nothing was repeated; review current choices again.")


def review(request, selected, expected, password, code=""):
    current, owner = authority(request, expected)
    local_owner._local(request, mutate=True)
    local_owner.verify_recovery(request, email=owner["email"], password=password, flow=ACTIVATION_FLOW, code=code)
    with settings_store._locked(strict=True):
        authority(request, current)
        proof = _proof(request, selected)
        layers, state, choice = _choice()
        if state["value"] is not False:
            raise HTTPException(409, "Company sign-in is already active. Read the original request or use its separate recovery review.")
        value = {"purpose": PURPOSE, "kind": "activation", "operation": secrets.token_hex(16),
                 "nonce": secrets.token_hex(16), "actor": auth.caller_principal(request), "context": current,
                 "owner_claim": _claim_binding(owner), "proof": proof["id"], "proof_revision": proof["revision"],
                 "material": proof["configuration"], "account": proof["account"], "provider": proof["provider"],
                 "before_choice": choice, "before_revision": native._revision(layers), "expires": time.time() + TTL}
        return {"context": current, "operation": value["operation"], "token": _seal(value), "notice": NOTICE,
                "changes": {"Current sign-in": "This computer's owner and invited colleagues use passphrases.",
                            "Verified company account": proof.get("account_label", "Verified company account"),
                            "Saved sign-in provider": proof["provider"],
                            "Sign-in checked": time.strftime("%b %d, %Y, %H:%M:%S", time.localtime(proof["checked_at"])),
                            "After this change": "People use the verified company sign-in provider.",
                            "Administrator access": "The verified company account already has installation administrator access. No role will change.",
                            "Recovery": "Only the original owner, on this computer, can separately review restoring the previous company-sign-in choice."}}


def _activation_guard(request, value):
    with auth.fresh_configuration():
        verified = auth._resolve_principal(request=request)
        if verified is None or verified.principal != value["actor"]:
            raise HTTPException(401, "The original owner session is no longer current. Sign in again before activation.")
        current, owner = authority(request, value["context"])
        _deadline(value)
        if auth.caller_principal(request) != value["actor"] or _claim_binding(owner) != value["owner_claim"] or native._revision() != value["before_revision"]:
            raise HTTPException(409, "The owner, access or settings changed after review. Nothing was repeated.")
        proof = _proof(request, value["proof"])
        if proof["revision"] != value["proof_revision"] or proof["configuration"] != value["material"]:
            raise HTTPException(409, "The reviewed company sign-in changed. Review its current result again.")
        step_up.require_recent_mfa(request, "change_auth_settings")
        _deadline(value)
        if native._revision() != value["before_revision"] or _claim_binding(_owner()) != value["owner_claim"]:
            raise HTTPException(409, "Owner authority or configuration changed while the sign-in proof was checked. Nothing was repeated.")
        return current


def guarded_transition(request, after_cfg):
    """Only a native sealed migration can authorize the activation lock-out guard."""
    value = getattr(request.state, "company_signin_migration", None)
    if not value:
        return None
    if value.get("protocol") == "saml":
        from .company_saml_setup import transition
        return transition(request, after_cfg)
    if value["kind"] == "activation":
        _activation_guard(request, value)
        return "You will be signed out. Use the company account you verified; the original owner has a separate, restricted recovery form on this computer."
    _recovery_guard(request, value)
    after = native.settings_access_guard.access_for(after_cfg)
    if not native.settings_access_guard._owner_can_return(request, value["actor"], after_cfg, after):
        raise HTTPException(409, "The previous choice would not restore a permitted owner sign-in. No settings were changed.")
    return "Only the previous company-sign-in choice will be restored. Sign in again with this computer's owner account."


def _original(row):
    confirmed = bool(row and row.get("state") == "confirmed" and not row.get("_audit_pending"))
    action = "restoration" if row and row.get("kind") == "recovery" else "activation"
    state = "audit_pending" if row and row.get("_audit_pending") else row.get("state", "unconfirmed") if row else "unconfirmed"
    messages = {"confirmed": f"Your original sign-in {action} was recorded. Nothing was repeated. Current sign-in settings are separate.",
                "approval": "Your original request awaits independent settings approval. This request did not activate company sign-in. Nothing was repeated.",
                "refused": "Your original sign-in request was refused. Nothing was repeated. Inspect current settings before reviewing a new change.",
                "audit_pending": "The original sign-in outcome has not yet been confirmed in the activity record. Nothing was repeated. Read its original result again when recording is available."}
    return {"confirmed": confirmed, "message": messages.get(state, f"The original sign-in {action} is unconfirmed. Nothing was repeated. Inspect current sign-in and separately review recovery if needed."),
            "recorded_at": row.get("updated_at") if row else None,
            "state": state}


def _lookup(operation, owner):
    if not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(404, "Choose an original sign-in request.")
    with deployment():
        row = store().get("CSM-" + operation)
        if row and row.get("_audit_pending"):
            row = store()._flush(row)
    if row and (row["actor"] != "user:" + owner["email"] or row["owner_claim"] != _claim_binding(owner)):
        raise HTTPException(404, "This original sign-in request belongs to a different owner.")
    return row


def original(request, operation, expected):
    current, owner = authority(request, expected)
    row = _lookup(operation, owner)
    authority(request, current)
    return {"context": current, "operation": operation, **_original(row)}


def _perform(request, value, guard):
    auth.require_global_permission(request, "admin")
    if auth.caller_principal(request) != value["actor"]:
        raise HTTPException(403, "This original sign-in review belongs to another account.")
    existing = _lookup(value["operation"], _owner())
    if existing:
        if existing["nonce"] != value["nonce"] or existing["kind"] != value["kind"]:
            raise HTTPException(409, "This request identifies another original review. Nothing was repeated.")
        return {"operation": value["operation"], **_original(existing)}
    guard()
    with deployment():
        row = store().create({**value, "id": "CSM-" + value["operation"], "state": "started"},
                             actor=value["actor"], action="company_signin_" + value["kind"] + "_started",
                             max_records=MAX_RECORDS, effect_guard=guard)
    if row.get("_audit_pending"):
        raise HTTPException(503, "The original request record is unconfirmed. No sign-in save was attempted; read its original result.")
    request.state.company_signin_migration = value
    try:
        change = {"id": value.get("setting", SETTING), "value": True} if value["kind"] == "activation" else _restoration_change(value)
        body = native.CatalogUpdate(expected_revision=value["before_revision"], changes=[native.SettingChange(**change)], confirm=True)
        response = native._catalog_update_locked(request, body, effect_guard=guard)
        payload = json.loads(response.body)
        state = "confirmed" if response.status_code == 200 else "approval" if response.status_code == 202 else "refused"
        with deployment():
            row = store().update(row["id"], lambda saved: saved.update(state=state), expected_revision=row["revision"],
                                 actor=value["actor"], action="company_signin_" + value["kind"] + "_completed")
        return {"operation": value["operation"], **_original(row), "detail": payload.get("message", payload.get("detail", ""))}
    except Exception as exc:
        if isinstance(exc, HTTPException) and exc.status_code in {401, 403}:
            raise
        return {"operation": value["operation"], **_original(_lookup(value["operation"], _owner()))}
    finally:
        del request.state.company_signin_migration


def activate(request, token):
    value = _opened(token)
    if value["kind"] != "activation":
        raise HTTPException(409, "Choose the reviewed activation request.")
    local_owner._local(request, mutate=True)
    with settings_store._locked(strict=True):
        return _perform(request, value, lambda: _activation_guard(request, value))


def recovery_identity(request, email, password, code=""):
    local_owner._local(request, mutate=True)
    with authority_effect_fence():
        _policy(request)
        row = local_owner.verify_recovery(request, email=email, password=password, flow=RECOVERY_FLOW, code=code)
        return row


def recovery_catalog(request, email, password, code=""):
    owner = recovery_identity(request, email, password, code)
    rows = [row for row in _records() if row["actor"] == "user:" + owner["email"] and row["owner_claim"] == _claim_binding(owner)]
    return {"notice": NOTICE, "requests": [{"value": row["id"][4:], "kind": row["kind"],
            "label": ("Restore previous sign-in" if row["kind"] == "recovery" else "Enable company sign-in")
            + " / " + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))} for row in rows]}


def recovery_original(request, operation, email, password, code=""):
    owner = recovery_identity(request, email, password, code)
    row = _lookup(operation, owner)
    _policy(request)
    _owner()
    return {"operation": operation, **_original(row)}


def recovery_review(request, operation, email, password, code=""):
    owner = recovery_identity(request, email, password, code)
    with settings_store._locked(strict=True):
        row = _lookup(operation, owner)
        if not row or row["kind"] != "activation" or row.get("_audit_pending"):
            raise HTTPException(409, "Choose a retained activation request whose original admission was recorded.")
        _layers, state, _choice_value = _choice()
        if state["value"] is not True or company_signin_tests.configuration_key(company_signin_tests.current_configuration()) != row["material"]:
            raise HTTPException(409, "Current sign-in differs from this retained activation. This recovery cannot replace those changes.")
        value = {"purpose": PURPOSE, "kind": "recovery", "operation": secrets.token_hex(16), "nonce": secrets.token_hex(16),
                 "actor": row["actor"], "owner_claim": row["owner_claim"], "migration": row["id"], "migration_revision": row["revision"],
                 "material": row["material"], "before_choice": row["before_choice"], "before_revision": native._revision(), "expires": time.time() + TTL}
        return {"operation": value["operation"], "token": _seal(value), "notice": NOTICE,
                "changes": {"Current sign-in": "Company sign-in is active with the same provider details as this retained activation.",
                            "After this change": "The previous company-sign-in choice will apply. Owner and invited-colleague passphrase sign-in will resume only where current policy permits it.",
                            "Other settings": "No provider credentials, roles, proxy settings, enterprise policy or second-factor requirement will change."}}


def _recovery_guard(request, value):
    local_owner._local(request, mutate=True)
    with auth.fresh_configuration():
        _policy(request)
        owner = _owner()
        _deadline(value)
        if _claim_binding(owner) != value["owner_claim"] or native._revision() != value["before_revision"]:
            raise HTTPException(409, "Owner authority or current sign-in changed after review. Nothing was repeated.")
        row = _lookup(value["migration"][4:], owner)
        if not row or row["revision"] != value["migration_revision"] or row["material"] != value["material"] or row.get("_audit_pending"):
            raise HTTPException(409, "The retained activation changed. Review current recovery choices again.")
        if company_signin_tests.configuration_key(company_signin_tests.current_configuration()) != value["material"]:
            raise HTTPException(409, "The current provider details changed. This recovery cannot replace them.")
        body = native.CatalogUpdate(expected_revision=value["before_revision"], changes=[native.SettingChange(**_restoration_change(value))], confirm=True)
        writes, _changes, _weakening, layers = native._plan(body)
        after_cfg = native.settings_access_guard.merged_config(layers, writes)
        after_cfg = native.settings_access_guard._deep_merge(after_cfg, layers["tenant"])
        after = native.settings_access_guard.access_for(after_cfg)
        if not native.settings_access_guard._owner_can_return(request, value["actor"], after_cfg, after):
            raise HTTPException(409, "Current policy would not permit owner sign-in after this restoration. No sign-in choice was changed.")
        step_up.require_recent_mfa(request, "change_auth_settings")
        _deadline(value)
        if native._revision() != value["before_revision"] or _claim_binding(_owner()) != value["owner_claim"]:
            raise HTTPException(409, "Owner authority or sign-in sources changed while the retained review was checked. Nothing was repeated.")


def _restoration_change(value):
    choice = value["before_choice"]
    setting = value.get("setting", SETTING)
    if choice.get("reset"):
        return {"id": setting, "reset": True}
    return {"id": setting, "value": choice["value"], "inherit": not choice["present"]}


def recover(request, token, email, password, code=""):
    value = _opened(token)
    if value["kind"] != "recovery":
        raise HTTPException(409, "Choose the separately reviewed recovery request.")
    owner = recovery_identity(request, email, password, code)
    if "user:" + owner["email"] != value["actor"] or _claim_binding(owner) != value["owner_claim"]:
        raise HTTPException(403, "This review belongs to a different local owner.")
    from maverick.oidc import VerifiedPrincipal
    request.state.principal = VerifiedPrincipal(sub=owner["email"], issuer="owner-recovery", audience="", claims={"via": "owner-recovery"})
    try:
        with settings_store._locked(strict=True):
            return _perform(request, value, lambda: _recovery_guard(request, value))
    finally:
        request.state.principal = None
