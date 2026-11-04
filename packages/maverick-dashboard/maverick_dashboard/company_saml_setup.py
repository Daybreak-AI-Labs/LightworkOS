"""Ordinary protected SAML setup; real tests never enable sign-in or grant roles."""
from __future__ import annotations

import secrets
import time
from dataclasses import asdict
from urllib.parse import urlparse

from fastapi import HTTPException
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.web_session import sign_session, verify_session

from . import (
    auth,
    company_saml_materials,
    company_signin_tests,
    local_owner,
    saml,
    settings_store,
    step_up,
)
from . import company_signin_migration as migration
from . import settings_all_page as native
from .draft_api import context_for

COOKIE = "mvk_saml_setup_test"
SETTING = "auth.saml.enabled"
ACTIVATION_FLOW = "company-saml-activation"  # the owner's activation review (passphrase and code)
RECOVERY_FLOW = "company-saml-recovery"  # the restricted recovery form (passphrase and code)
NOTICE = ("First save these files and details as an inactive setup. Trying sign-in verifies the "
          "provider's actual signed response without signing anyone into Lightwork or granting a role. "
          "Reviewing uploads keeps an encrypted copy before any sign-in setting changes. "
          "Separately grant the verified person administrator access, then review activation. "
          "The original owner can review restoring only the previous single-sign-on choice on this computer.")


def store():
    return GovernedRecordStore("company-saml-setups", "SST", "company_saml_setup",
                               authority_scope="deployment_global")


def authority(request, expected=None, *, active=False):
    local_owner._local(request)
    current = company_signin_tests.authority(request, expected)
    owner = migration._owner()
    if auth.caller_principal(request) != "user:" + owner["email"]:
        raise HTTPException(403, "Use this computer's original owner account for sign-in setup.")
    _policy(request, active=active)
    return current, owner


def _policy(request, *, active=False):
    from maverick import config
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Current sign-in policy cannot be checked. Nothing was enabled.")
    cfg = config.load_config()
    access = native.settings_access_guard.access_for(cfg)
    from .ip_allowlist import installation_allows, workspace_allows
    from .mfa_policy import require_mfa
    if (access.token_env or access.proxy or access.client_enforced or access.oidc
            or access.saml_policy and not active or require_mfa()
            or not installation_allows(request) or not workspace_allows(request)):
        raise HTTPException(403, "Current installation policy does not permit this local-owner single-sign-on setup or recovery.")
    return cfg


def configuration_key(cfg=None):
    value = asdict(cfg or saml.load_saml_config())
    value.pop("enabled", None)
    return digest([value, saml._session_secret()])


def _rows():
    with migration.deployment():
        rows = store().list(limit=1001)
    if len(rows) > 1000:
        raise HTTPException(503, "The retained single-sign-on setup list exceeds its supported bound.")
    return rows


def catalog(request):
    current, _owner = authority(request)
    from .saml import runtime_readiness
    key = configuration_key()
    checks = company_signin_tests.STORE.list(limit=101)
    if len(checks) > 100:
        raise HTTPException(503, "The retained sign-in checks exceed this view's supported bound.")
    def owned(row):
        return row.get("actor") == auth.caller_principal(request) and row.get("owner") == context_for(request)
    selected = [row for row in checks if owned(row) and row.get("protocol") == "saml"
                and row.get("configuration") == key and not row.get("_audit_pending")]
    original = [row for row in _rows() if owned(row)]
    authority(request, current)
    return {"context": current, "notice": NOTICE, "runtime": runtime_readiness(),
            "checks": [{"value": row["id"], "label": row["account_label"] + " / " + time.strftime("%b %d, %H:%M", time.localtime(row["checked_at"]))} for row in selected],
            "requests": [{"value": row["id"][4:], "label": row["name"] + " / " + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))} for row in original],
            "activations": _migration_choices(request)}


def upload_review(request, fields, metadata, certificate, key, password, expected):
    current, owner = authority(request, expected)
    local_owner._local(request, mutate=True)
    material, summary = company_saml_materials.validate(metadata, certificate, key, password)
    origin = urlparse(str(request.base_url))
    if origin.scheme != "https":
        raise HTTPException(409, "Use this site's HTTPS address for single sign-on. The provider's browser return requires a secure connection.")
    name, entity = fields["name"].strip(), fields["entity"].strip()
    if not name or len(name) > 120 or any(ord(char) < 32 for char in name):
        raise HTTPException(422, "Give this provider a readable name of up to 120 characters.")
    entity = native.catalog.coerce(native.catalog.BY_ID["auth.saml.sp_entity_id"], entity)
    operation, material_id = secrets.token_hex(16), "SMD-" + secrets.token_hex(16)
    source = native._revision()
    expires = time.time() + migration.TTL
    def guard():
        with auth.fresh_configuration():
            authority(request, current)
            if native._revision() != source or time.time() >= expires:
                raise HTTPException(409, "The current settings changed or this file review expired. Nothing was enabled.")
    with authority_effect_fence(), settings_store._locked(strict=True):
        guard()
        retained = company_saml_materials.retain(material_id, material, summary, actor=auth.caller_principal(request), owner=context_for(request), guard=guard)
        if retained.get("_audit_pending"):
            raise HTTPException(503, "The uploaded files have not been confirmed in the activity record. No setup was saved.")
        changes = {"auth.saml.enabled": False, "auth.saml.sp_entity_id": entity,
                   "auth.saml.acs_url": str(request.base_url).rstrip("/") + "/saml/acs",
                   "auth.saml.idp_metadata_file": company_saml_materials.PREFIX + material_id,
                   "auth.saml.want_assertions_signed": True}
        resets = ["auth.saml.idp_metadata_url", "auth.saml.sp_cert_file", "auth.saml.sp_key_file"]
        row = {"id": "SST-" + operation, "actor": auth.caller_principal(request), "owner": context_for(request),
               "owner_claim": migration._claim_binding(owner), "name": name, "source": source, "expires": expires,
               "material": retained["id"], "material_revision": retained["revision"], "changes": changes, "resets": resets, "state": "reviewed"}
        with migration.deployment():
            saved = store().create(row, actor=row["actor"], action="company_saml_setup_reviewed", max_records=1000, effect_guard=guard)
        if saved.get("_audit_pending"):
            raise HTTPException(503, "The complete setup review could not be recorded. Nothing was enabled.")
    return {"context": current, "operation": operation, "notice": NOTICE,
            "changes": {"Current sign-in": "Single sign-on is inactive. Current owner sign-in and permissions remain unchanged while staging.",
                        "Setup name": name, **summary, "Lightwork name at the provider": entity,
                        "Return address": changes["auth.saml.acs_url"], "Sign-ins must be signed": True,
                        "After saving": "Single sign-on remains inactive. Existing metadata addresses and file choices are replaced by the uploaded protected files.",
                        "Stored files": "Encrypted on this installation. Private key bytes are never shown or sent to Copilot."}}


def _original(row):
    confirmed = bool(row and row.get("state") == "confirmed" and not row.get("_audit_pending"))
    state = "audit_pending" if row and row.get("_audit_pending") else row.get("state", "unknown") if row else "unknown"
    message = ("The original inactive setup was saved. Nothing was repeated. Try its real sign-in before activation." if confirmed else
               "The original setup outcome is unconfirmed. Nothing was repeated. Inspect current settings before a separate new review.")
    if state == "reviewed":
        message = "This complete setup was reviewed but has not been applied."
    if state == "refused":
        message = "The inactive setup was refused and was not saved. Keep the files and review a corrected setup."
    if state == "approval":
        message = "This setup was submitted for independent approval. It is not confirmed as saved; check current approval and settings before another review."
    return {"confirmed": confirmed, "state": state, "message": message}


def original(request, operation, expected):
    current, _owner = authority(request, expected, active=True)
    row = _selected(request, operation)
    authority(request, current, active=True)
    return {"context": current, "operation": operation, **_original(row)}


def _selected(request, operation):
    if not isinstance(operation, str) or len(operation) != 32 or any(char not in "0123456789abcdef" for char in operation):
        raise HTTPException(404, "Choose one of your retained single-sign-on setup requests.")
    with migration.deployment():
        row = store().get("SST-" + operation)
        if row and row.get("_audit_pending"):
            row = store()._flush(row)
    if not row or row["actor"] != auth.caller_principal(request) or row["owner"] != context_for(request):
        raise HTTPException(404, "This original setup belongs to another account or workspace.")
    return row


def apply(request, operation, expected):
    current, owner = authority(request, expected)
    local_owner._local(request, mutate=True)
    with authority_effect_fence(), settings_store._locked(strict=True):
        row = _selected(request, operation)
        if row["state"] != "reviewed":
            return {"operation": operation, **_original(row)}
        def guard():
            with auth.fresh_configuration():
                authority(request, current)
                if native._revision() != row["source"] or migration._claim_binding(migration._owner()) != row["owner_claim"] or time.time() >= row["expires"]:
                    raise HTTPException(409, "The settings, owner or complete review changed. Keep the files and review the current setup again.")
                material, _bytes = company_saml_materials.resolve(company_saml_materials.PREFIX + row["material"])
                if material["revision"] != row["material_revision"]:
                    raise HTTPException(409, "The reviewed provider files changed. Nothing was repeated.")
                step_up.require_recent_mfa(request, "change_auth_settings")
                if native._revision() != row["source"] or time.time() >= row["expires"]:
                    raise HTTPException(409, "Current settings changed or this complete review expired while checking its files.")
        guard()
        with migration.deployment():
            row = store().update(row["id"], lambda saved: saved.update(state="started"), expected_revision=row["revision"],
                                 actor=row["actor"], action="company_saml_setup_started", effect_guard=guard)
        if row.get("_audit_pending"):
            return {"operation": operation, **_original(row)}
        try:
            body = native.CatalogUpdate(expected_revision=row["source"], confirm=True,
                                        changes=[native.SettingChange(id=name, value=value) for name, value in row["changes"].items()]
                                        + [native.SettingChange(id=name, reset=True) for name in row["resets"]])
            response = native._catalog_update_locked(request, body, effect_guard=guard)
            state = "confirmed" if response.status_code == 200 else "approval" if response.status_code == 202 else "refused"
            with migration.deployment():
                row = store().update(row["id"], lambda saved: saved.update(state=state), expected_revision=row["revision"],
                                     actor=row["actor"], action="company_saml_setup_completed")
        except Exception as exc:
            if isinstance(exc, HTTPException) and exc.status_code in {401, 403}:
                raise
            # The original is reserved. Reading it never automatically retries a settings write.
            row = _selected(request, operation)
        return {"operation": operation, **_original(row)}


def current_configuration():
    cfg = saml.load_saml_config()
    if (not cfg.sp_entity_id or not cfg.acs_url or not cfg.idp_metadata_file.startswith(company_saml_materials.PREFIX)
            or cfg.want_assertions_signed is not True or len(saml._session_secret()) < 32):
        raise HTTPException(409, "Save the inactive provider files, Lightwork name, HTTPS return address and protected session key before trying sign-in.")
    company_saml_materials.resolve(cfg.idp_metadata_file)
    return cfg


def _session_guard(transaction):
    from . import session_registry, session_revocation
    row = session_registry.get(transaction["session"])
    if (row is None or row.principal != transaction["actor"] or session_registry.status(row.sid) is not True
            or session_revocation.is_revoked(row.principal.removeprefix("user:"), row.issued_at)):
        raise HTTPException(401, "The owner session that started this sign-in check is no longer current.")
    return row


def start(request):
    current, _owner = authority(request)
    cfg = current_configuration()
    if request.url.scheme != "https":
        raise HTTPException(409, "Use this site's HTTPS address before trying single sign-on.")
    session = getattr(request.state.principal, "claims", {}).get("sid")
    if not session:
        raise HTTPException(401, "Sign in again with the owner account before trying single sign-on.")
    key = configuration_key(cfg)
    state = secrets.token_urlsafe(32)
    request_id, target = saml.prepare_login_redirect(cfg=cfg, relay_state=state)
    authority(request, current)
    if configuration_key(current_configuration()) != key or not request_id or urlparse(target).scheme != "https":
        raise HTTPException(409, "The current provider files changed or the provider sign-in address is unavailable.")
    transaction = {"purpose": "lightwork.saml-setup.v1", "actor": auth.caller_principal(request), "owner": context_for(request),
                   "context": current, "configuration": key, "state": state, "request_id": request_id,
                   "session": session, "expires": time.time() + migration.TTL, "exp": time.time() + migration.TTL,
                   "jti": secrets.token_hex(16)}
    _session_guard(transaction)
    return target, sign_session(transaction, saml._session_secret()), current


async def finish(request):
    """Verify the native signed assertion; retain a proof without a dashboard session."""
    from fastapi.responses import RedirectResponse
    from maverick.oidc import VerifiedPrincipal

    from . import saml_replay
    response = RedirectResponse("/settings/all?saml_test=unconfirmed#company-saml-setup", status_code=303)
    previous = getattr(request.state, "principal", None)
    try:
        transaction = verify_session(request.cookies.get(COOKIE, ""), saml._session_secret())
        if not transaction or transaction.get("purpose") != "lightwork.saml-setup.v1":
            return response
        _session_guard(transaction)
        request.state.principal = VerifiedPrincipal(sub=transaction["actor"].removeprefix("user:"), issuer="saml-setup-owner", audience="", claims={"via": "invite", "sid": transaction["session"]})
        def guard():
            with auth.fresh_configuration():
                _session_guard(transaction)
                authority(request, transaction["context"])
                if time.time() >= transaction["expires"] or configuration_key(current_configuration()) != transaction["configuration"]:
                    raise HTTPException(409, "This sign-in test expired or its exact provider details changed. Nothing was enabled.")
        guard()
        if not await saml._cache_limited_body(request, limit=saml._MAX_ACS_BODY_BYTES):
            return response
        form = await request.form()
        encoded = str(form.get("SAMLResponse") or "")
        if saml._form_value_too_large(encoded, limit=saml._MAX_SAML_RESPONSE_BYTES) or not secrets.compare_digest(str(form.get("RelayState") or "").encode(), transaction["state"].encode()):
            return response
        identity = saml.verify_acs_response(encoded, request_id=transaction["request_id"], cfg=current_configuration())
        guard()
        if (not identity.assertion_id or not saml_replay.consume("setup:" + transaction["jti"], transaction["expires"])
                or not saml_replay.consume(identity.assertion_id, identity.expires_at)):
            return response
        label = "Verified company account"
        for field in ("displayName", "name", "cn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"):
            values = identity.attributes.get(field, [])
            if values and isinstance(values[0], str) and 0 < len(values[0]) <= 120 and all(ord(char) >= 32 for char in values[0]):
                label = values[0]
                break
        with authority_effect_fence():
            row = company_signin_tests.STORE.create({"id": "CST-" + digest(transaction["jti"])[:32], "actor": transaction["actor"],
                "owner": transaction["owner"], "configuration": transaction["configuration"], "protocol": "saml", "checked_at": time.time(),
                "provider": "Single sign-on", "account": identity.name_id, "account_label": label},
                actor=transaction["actor"], action="company_saml_signin_verified", max_records=100, effect_guard=guard)
        if not row.get("_audit_pending"):
            response = RedirectResponse("/settings/all?saml_test=verified#company-saml-setup", status_code=303)
    except Exception:
        pass  # Never echo XML, private files, tokens or provider diagnostics.
    finally:
        request.state.principal = previous
        response.delete_cookie(COOKIE, path="/saml")
    return response


def _migration_choices(request):
    owner = migration._owner()
    return [{"value": row["id"][4:], "label": ("Restore previous single sign-on" if row["kind"] == "recovery" else "Enable single sign-on")
             + " / " + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))}
            for row in migration._records() if row.get("protocol") == "saml" and row["actor"] == auth.caller_principal(request)
            and row["owner_claim"] == migration._claim_binding(owner)]


def verified_people(request):
    current = company_signin_tests.authority(request)
    key = configuration_key()
    rows = company_signin_tests.STORE.list(limit=101)
    if len(rows) > 100:
        raise HTTPException(503, "The retained sign-in checks exceed the supported bound.")
    people = {}
    for row in rows:
        if (row.get("protocol") == "saml" and row.get("actor") == auth.caller_principal(request)
                and row.get("owner") == context_for(request) and row.get("configuration") == key
                and not row.get("_audit_pending") and 0 <= time.time() - row["checked_at"] < migration.TTL):
            people["user:" + row["account"]] = row["account_label"] + " (verified single sign-on)"
    company_signin_tests.authority(request, current)
    return people


def _proof(request, selected):
    row = company_signin_tests.STORE.get(selected)
    if (not row or row.get("protocol") != "saml" or row.get("actor") != auth.caller_principal(request)
            or row.get("owner") != context_for(request) or row.get("_audit_pending")):
        raise HTTPException(404, "Choose one of your verified single sign-ons.")
    if not 0 <= time.time() - row["checked_at"] < migration.TTL or row["configuration"] != configuration_key(current_configuration()):
        raise HTTPException(409, "Try the current single sign-on again before activation. The reviewed check changed or expired.")
    from maverick.oidc import VerifiedPrincipal
    from maverick.suite_grants import admin_principals

    from . import rbac
    auth._enforce_scim_active(VerifiedPrincipal(sub=row["account"], issuer="saml", audience="", claims={}))
    principal = "user:" + row["account"]
    role = rbac.get_stored_role(principal)
    if principal not in admin_principals() and (role is None or "admin" not in rbac.permissions_for(role)):
        raise HTTPException(409, "Give this verified person installation administrator access on People, then review activation. No role is granted here.")
    return row


def _choice():
    layers = native._sources()
    setting = native.catalog.BY_ID[SETTING]
    if native.catalog.lookup(layers["tenant"], setting.path)[0]:
        raise HTTPException(409, "Workspace policy controls this single-sign-on choice. This installation form cannot replace it.")
    state = native._resolve(setting, layers)
    if state["locked"] or not state["known"]:
        raise HTTPException(409, "Installer or server policy controls this single-sign-on choice. It cannot be replaced here.")
    present, value = native._layer_value(setting, layers["here"])
    from maverick.config_resets import is_reset
    return layers, state, {"present": present, "value": value if present else None, "reset": is_reset(layers["here"], setting)}


def activation_review(request, selected, expected, password, code=""):
    current, owner = authority(request, expected)
    local_owner._local(request, mutate=True)
    local_owner.verify_recovery(request, email=owner["email"], password=password, flow=ACTIVATION_FLOW, code=code)
    with authority_effect_fence(), settings_store._locked(strict=True):
        proof = _proof(request, selected)
        cfg = current_configuration()
        if not saml.runtime_readiness()["ready"] or cfg.enabled:
            raise HTTPException(409, "Save an inactive setup with installed single-sign-on support before activation.")
        layers, _state, choice = _choice()
        value = {"purpose": migration.PURPOSE, "protocol": "saml", "setting": SETTING, "kind": "activation",
                 "operation": secrets.token_hex(16), "nonce": secrets.token_hex(16), "actor": auth.caller_principal(request),
                 "context": current, "owner_claim": migration._claim_binding(owner), "proof": proof["id"],
                 "proof_revision": proof["revision"], "material": configuration_key(cfg), "account": proof["account"],
                 "provider": proof["provider"], "before_choice": choice, "before_revision": native._revision(layers),
                 "expires": time.time() + migration.TTL}
        _activation_guard(request, value)
        return {"context": current, "operation": value["operation"], "token": migration._seal(value), "notice": NOTICE,
                "changes": {"Current sign-in": "Single sign-on is inactive; the owner uses a passphrase.",
                            "Verified person": proof["account_label"], "Checked at": time.strftime("%b %d, %Y, %H:%M:%S", time.localtime(proof["checked_at"])),
                            "After activation": "People use the tested single-sign-on provider. No role or provider file changes.",
                            "Administrator access": "The verified person already has installation administrator access.",
                            "Recovery": "The original owner may separately restore only this prior single-sign-on choice on this computer."}}


def _activation_guard(request, value):
    with auth.fresh_configuration():
        verified = auth._resolve_principal(request=request)
        if verified is None or verified.principal != value["actor"]:
            raise HTTPException(401, "The original owner session is no longer current.")
        authority(request, value["context"])
        migration._deadline(value)
        proof = _proof(request, value["proof"])
        if (proof["revision"] != value["proof_revision"] or configuration_key() != value["material"]
                or migration._claim_binding(migration._owner()) != value["owner_claim"]):
            raise HTTPException(409, "The verified sign-in or original owner changed. Nothing was enabled.")
        step_up.require_recent_mfa(request, "change_auth_settings")
        migration._deadline(value)
        if native._revision() != value["before_revision"]:
            raise HTTPException(409, "The reviewed sign-in settings changed. Nothing was enabled.")


def activate(request, token):
    value = migration._opened(token)
    if value.get("protocol") != "saml" or value["kind"] != "activation":
        raise HTTPException(409, "Choose the reviewed single-sign-on activation.")
    local_owner._local(request, mutate=True)
    with authority_effect_fence(), settings_store._locked(strict=True):
        return migration._perform(request, value, lambda: _activation_guard(request, value))


def migration_original(request, operation, expected):
    current, owner = authority(request, expected, active=True)
    row = migration._lookup(operation, owner)
    if row and row.get("protocol") != "saml":
        raise HTTPException(404, "Choose an original single-sign-on request.")
    authority(request, current, active=True)
    return {"context": current, "operation": operation, **migration._original(row)}


def recovery_identity(request, email, password, code=""):
    local_owner._local(request, mutate=True)
    with authority_effect_fence():
        _policy(request, active=True)
        return local_owner.verify_recovery(request, email=email, password=password, flow=RECOVERY_FLOW, code=code)


def recovery_catalog(request, email, password, code=""):
    owner = recovery_identity(request, email, password, code)
    rows = [row for row in migration._records() if row.get("protocol") == "saml"
            and row["actor"] == "user:" + owner["email"] and row["owner_claim"] == migration._claim_binding(owner)]
    return {"notice": NOTICE, "requests": [{"value": row["id"][4:], "kind": row["kind"], "label": ("Restore previous sign-in" if row["kind"] == "recovery" else "Enable single sign-on")
            + " / " + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))} for row in rows]}


def recovery_original(request, operation, email, password, code=""):
    owner = recovery_identity(request, email, password, code)
    row = migration._lookup(operation, owner)
    if row and row.get("protocol") != "saml":
        raise HTTPException(404, "Choose an original single-sign-on request.")
    _policy(request, active=True)
    migration._owner()
    return {"operation": operation, **migration._original(row)}


def recovery_review(request, operation, email, password, code=""):
    owner = recovery_identity(request, email, password, code)
    with authority_effect_fence(), settings_store._locked(strict=True):
        row = migration._lookup(operation, owner)
        if not row or row.get("protocol") != "saml" or row["kind"] != "activation" or row.get("_audit_pending"):
            raise HTTPException(409, "Choose a retained activation whose original admission was recorded.")
        _layers, state, _choice_value = _choice()
        if state["value"] is not True or configuration_key() != row["material"]:
            raise HTTPException(409, "Current single sign-on differs from the retained activation. This recovery cannot replace those changes.")
        value = {"purpose": migration.PURPOSE, "protocol": "saml", "setting": SETTING, "kind": "recovery",
                 "operation": secrets.token_hex(16), "nonce": secrets.token_hex(16), "actor": row["actor"],
                 "owner_claim": row["owner_claim"], "migration": row["id"], "migration_revision": row["revision"],
                 "material": row["material"], "before_choice": row["before_choice"], "before_revision": native._revision(),
                 "expires": time.time() + migration.TTL}
        return {"operation": value["operation"], "token": migration._seal(value), "notice": NOTICE,
                "changes": {"Current single sign-on": "Active with the exact same retained provider files and details.",
                            "After restoration": "Only the previous single-sign-on choice applies. Owner sign-in resumes only where current installation policy permits it.",
                            "Unchanged": "No provider files, passwords, roles, proxy settings, enterprise or second-factor policies change."}}


def _recovery_guard(request, value):
    local_owner._local(request, mutate=True)
    with auth.fresh_configuration():
        _policy(request, active=True)
        owner = migration._owner()
        row = migration._lookup(value["migration"][4:], owner)
        if (not row or row["revision"] != value["migration_revision"] or row.get("_audit_pending")
                or migration._claim_binding(owner) != value["owner_claim"] or configuration_key() != value["material"]):
            raise HTTPException(409, "The retained activation, owner or exact current provider details changed. Nothing was restored.")
        body = native.CatalogUpdate(expected_revision=value["before_revision"], confirm=True,
            changes=[native.SettingChange(**migration._restoration_change(value))])
        writes, _changes, _weakening, layers = native._plan(body)
        prospective = native.settings_access_guard.merged_config(layers, writes)
        prospective = native.settings_access_guard._deep_merge(prospective, layers["tenant"])
        if not local_owner.sign_in_available_for(prospective):
            raise HTTPException(409, "The previous choice would not permit owner sign-in under current policy.")
        step_up.require_recent_mfa(request, "change_auth_settings")
        migration._deadline(value)
        if native._revision() != value["before_revision"]:
            raise HTTPException(409, "The current sign-in settings changed after recovery review. Nothing was restored.")


def recover(request, token, email, password, code=""):
    value = migration._opened(token)
    if value.get("protocol") != "saml" or value["kind"] != "recovery":
        raise HTTPException(409, "Choose the separately reviewed single-sign-on recovery.")
    owner = recovery_identity(request, email, password, code)
    if value["actor"] != "user:" + owner["email"] or value["owner_claim"] != migration._claim_binding(owner):
        raise HTTPException(403, "This recovery review belongs to another original owner.")
    from maverick.oidc import VerifiedPrincipal
    request.state.principal = VerifiedPrincipal(sub=owner["email"], issuer="owner-recovery", audience="", claims={"via": "owner-recovery"})
    try:
        with authority_effect_fence(), settings_store._locked(strict=True):
            return migration._perform(request, value, lambda: _recovery_guard(request, value))
    finally:
        request.state.principal = None


def transition(request, after_cfg):
    value = getattr(request.state, "company_signin_migration", None)
    if not value or value.get("protocol") != "saml":
        return None
    if value["kind"] == "activation":
        _activation_guard(request, value)
        return "You will be signed out. Use the verified person who already has administrator access. The original owner has a separately reviewed recovery on this computer."
    _recovery_guard(request, value)
    if not local_owner.sign_in_available_for(after_cfg):
        raise HTTPException(409, "The actual restored choice would not permit owner sign-in.")
    return "Only the previous single-sign-on choice will be restored. Sign in again with this computer's owner account."
