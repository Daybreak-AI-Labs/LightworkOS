"""Reviewed in-app activation and workspace connection binding, without probes."""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Request, Response
from maverick import config, connections
from maverick import vendor_onboarding_setup as setup
from maverick.governed_records import RecordConflict
from maverick.paths import current_tenant_id_strict
from maverick.vendor_onboarding import deployment_readiness
from pydantic import BaseModel, ConfigDict, Field

from . import rbac, scim_groups, settings_store
from .auth import (
    caller_principal,
    constant_time_equals,
    require_global_permission,
    role_for_principal,
)
from .draft_api import context_for
from .workflow_readiness import supplier_setup_readiness

router = APIRouter(prefix="/api/v1/vendor-setup", tags=["vendor-setup"])


class Reviewed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    confirm: bool
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    configuration: str = Field(pattern=r"^[a-f0-9]{64}$")


class BindingIn(Reviewed):
    expected_revision: int = Field(ge=0)
    ticket: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    document: str = Field(default="", max_length=64)
    ticket_revision: str = Field(min_length=1, max_length=64)
    document_revision: str = Field(default="", max_length=64)
    resource_owner: str = Field(min_length=1, max_length=256)


def _eligible_owner(tenant, principal):
    return (current_tenant_id_strict() == tenant and isinstance(principal, str)
        and principal.startswith("user:") and len(principal) > 5
        and principal in rbac.list_tenant_roles(tenant)
        and scim_groups.active_for_principal(principal) is not False
        and "operate" in rbac.permissions_for(role_for_principal(principal)))


def _configuration():
    global_config, effective = config.load_global_config(), config.load_config()
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Configuration is unavailable. No setup settings were changed.")
    selected = [{key: value.get(key) for key in setup.REQUIRED_MODULES}
                for value in (global_config, effective)]
    selected.append({"connections_override": connections.deployment_override()})
    selected.append({"deployment": deployment_readiness()})
    return hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest(), global_config


def _authority(request, response, payload=None):
    require_global_permission(request, "admin")
    actor = caller_principal(request)
    if not actor or not actor.startswith("user:") or not current_tenant_id_strict():
        raise HTTPException(403, "Sign in as an administrator and select a workspace.")
    response.headers["Cache-Control"] = "private, no-store"
    fingerprint, loaded = _configuration()
    supplied = request.headers.get("X-Lightwork-Setup-Context")
    if supplied is not None and not constant_time_equals(supplied, context_for(request)):
        raise HTTPException(409, "Your account or workspace changed. Reload setup.")
    if payload is not None:
        from .app import _require_same_origin
        _require_same_origin(request)
        if payload.confirm is not True:
            raise HTTPException(422, "Review and confirm the setup change.")
        if not hmac.compare_digest(payload.context, context_for(request)) or not hmac.compare_digest(payload.configuration, fingerprint):
            raise HTTPException(409, "Account, workspace or settings changed. Reload and review setup.")
        profile = deployment_readiness()
        if not profile["supported"]:
            raise HTTPException(409, profile["message"] + " " + profile["next_action"])
    return actor, fingerprint, loaded


@router.get("")
def overview(request: Request, response: Response):
    actor, fingerprint, loaded = _authority(request, response)
    profile = deployment_readiness()
    if not profile["supported"]:
        # A diagnostic must not enter unsupported stores or acquire saga locks.
        state = {"context": context_for(request), "configuration": fingerprint,
            "revision": 0, "binding": {"resource_owner": "", "ticket_connection": "", "document_connection": ""},
            "owner_locked": False, "owner_source": "unavailable", "eligible_owners": [],
            "principal": actor, "connections_enabled": False, "modules_enabled": False,
            "connections": [], "live_provider_verified": False, "deployment": profile}
        return {**state, "readiness": supplier_setup_readiness(state)}
    try:
        record = setup.current()
        ownership = setup.owner_policy()
        candidates = connections.list_connections(owner=actor) if connections.enabled() else []
        binding = record["binding"] if record else asdict(setup.VendorOnboardingSettings.from_config({"vendor_onboarding": dict(loaded.get("vendor_onboarding") or {}, enable=False)}))
        binding = dict(binding, resource_owner=ownership["resource_owner"])
        tenant = current_tenant_id_strict()
        eligible_owners = [] if ownership["owner_locked"] else sorted(
            principal for principal in rbac.list_tenant_roles(tenant) if _eligible_owner(tenant, principal))
        state = {"context": context_for(request), "configuration": fingerprint,
            "revision": (record or {}).get("revision", 0), "binding": binding,
            "owner_locked": ownership["owner_locked"], "owner_source": ownership["owner_source"],
            "eligible_owners": eligible_owners,
            "principal": actor, "connections_enabled": connections.enabled(),
            "modules_enabled": all((loaded.get(key) or {}).get("enable") is True for key in setup.REQUIRED_MODULES),
            "connections": [{key: row[key] for key in ("name", "connector", "base_url", "revision", "has_token")} for row in candidates if row["connector"] in {"jira", "gdrive"}],
            "live_provider_verified": False, "deployment": profile}
        return {**state, "readiness": supplier_setup_readiness(state)}
    except Exception as exc:
        raise HTTPException(503, "Vendor setup records are unavailable.") from exc


@router.post("/enable")
def enable(request: Request, response: Response, payload: Reviewed):
    _authority(request, response, payload)
    if connections.deployment_override() is False:
        raise HTTPException(409, "Deployment policy disables Connections.")
    from maverick.audit import AuditRefused, EventKind, audit_event
    with settings_store._locked(strict=True):
        actor, _, loaded = _authority(request, response, payload)
        turned_on = [key for key in setup.REQUIRED_MODULES
                     if (loaded.get(key) or {}).get("enable") is not True]
        before = settings_store._load_overlay_for_update()
        data = copy.deepcopy(before)
        for key in setup.REQUIRED_MODULES:
            data.setdefault(key, {})["enable"] = True
        settings_store._write(data)
        try:
            for key in turned_on:
                audit_event(EventKind.SETTING_CHANGED, agent="dashboard", _global=True, actor=actor,
                            section=key, key="enable", old=False, new=True, confirmed=True)
        except AuditRefused as exc:
            settings_store._write(before)
            config.reset_config_cache()
            raise HTTPException(503, "The change could not be recorded, so it was undone.") from exc
    config.reset_config_cache()
    state = overview(request, response)
    if not state["modules_enabled"] or not state["connections_enabled"]:
        raise HTTPException(409, "Deployment policy prevents this activation. Review current setup.")
    return state


@router.put("")
def bind(request: Request, response: Response, payload: BindingIn):
    actor, _, _ = _authority(request, response, payload)
    tenant = current_tenant_id_strict()
    try:
        setup.save(actor=actor, ticket=payload.ticket, document=payload.document,
            ticket_revision=payload.ticket_revision, document_revision=payload.document_revision,
            expected_revision=payload.expected_revision, resource_owner=payload.resource_owner,
            eligible_owner=lambda principal: _eligible_owner(tenant, principal))
    except (PermissionError, ValueError, RecordConflict) as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "Vendor setup was not confirmed. Reload before retrying.") from exc
    return overview(request, response)


def _reviewed_turn_off(request, response, payload):
    """The checks ``_authority`` makes for a change, without requiring a
    supported deployment profile: turning the workflow off must stay possible
    exactly when the deployment needs attention."""
    actor, fingerprint, _ = _authority(request, response)
    from .app import _require_same_origin
    _require_same_origin(request)
    if payload.confirm is not True:
        raise HTTPException(422, "Review and confirm the setup change.")
    if not hmac.compare_digest(payload.context, context_for(request)) or not hmac.compare_digest(payload.configuration, fingerprint):
        raise HTTPException(409, "Account, workspace or settings changed. Reload and review setup.")
    return actor


@router.post("/disable")
def disable(request: Request, response: Response, payload: Reviewed):
    """Turn vendor onboarding off for this installation. Nobody can start or
    continue a vendor request until it is turned on again; saved requests, the
    workspace setup and connections are kept, and the vendor, risk and evidence
    features turned on with it stay on (each has its own module switch)."""
    _reviewed_turn_off(request, response, payload)
    from maverick.audit import AuditRefused, EventKind, audit_event
    with settings_store._locked(strict=True):
        actor = _reviewed_turn_off(request, response, payload)
        was_on = (config.load_global_config().get("vendor_onboarding") or {}).get("enable") is True
        before = settings_store._load_overlay_for_update()
        data = copy.deepcopy(before)
        table = data.setdefault("vendor_onboarding", {})
        if not isinstance(table, dict):
            raise HTTPException(503, "Configuration is unavailable. No setup settings were changed.")
        table["enable"] = False
        settings_store._write(data)
        config.reset_config_cache()
        if (config.load_config().get("vendor_onboarding") or {}).get("enable") is True:
            settings_store._write(before)
            config.reset_config_cache()
            raise HTTPException(409, "Higher-precedence deployment settings keep vendor onboarding on. Nothing was changed.")
        if was_on:
            try:
                audit_event(EventKind.SETTING_CHANGED, agent="dashboard", _global=True, actor=actor,
                            section="vendor_onboarding", key="enable", old=True, new=False,
                            confirmed=True)
            except AuditRefused as exc:
                settings_store._write(before)
                config.reset_config_cache()
                raise HTTPException(503, "The change could not be recorded, so it was undone.") from exc
    return overview(request, response)
