"""Named renewable credentials; explicit consent and sealed app registration."""
from __future__ import annotations

import copy
import hashlib
import json
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request, Response
from maverick import config, connection_oauth, connections
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field

from . import settings_store
from .auth import (
    caller_principal,
    constant_time_equals,
    has_global_permission,
    has_permission,
    require_global_permission,
    require_permission,
)
from .draft_api import context_for

router = APIRouter(prefix="/api/v1/connection-setup", tags=["connection-setup"])


class Reviewed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    confirm: bool
    context: str = Field(pattern=r"^[a-f0-9]{64}$")


class ApplicationIn(Reviewed):
    provider: str = Field(max_length=32)
    client_id: str = Field(min_length=1, max_length=1024)
    client_secret: str | None = Field(default=None, max_length=4096)
    expected_revision: str = Field(default="", max_length=64)
    desktop_return: bool = False


class AuthorizeIn(Reviewed):
    profile: str = Field(max_length=64)
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    expected_revision: str = Field(default="", max_length=64)
    site_url: str = Field(default="", max_length=256)
    return_profile: Literal["browser", "desktop-loopback-v1"] = "browser"
    native_handle: str = Field(default="", max_length=64, pattern=r"^$|^[a-f0-9]{64}$")
    prepare_ticket: str = Field(default="", max_length=8192)


class NativePrepareIn(Reviewed):
    profile: str = Field(max_length=64)
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    expected_revision: str = Field(default="", max_length=64)
    site_url: str = Field(default="", max_length=256)


class ExchangeIn(Reviewed):
    state: str = Field(min_length=40, max_length=64)
    code: str = Field(min_length=1, max_length=8192)
    return_profile: Literal["browser", "desktop-loopback-v1"] = "browser"


class CancelIn(Reviewed):
    state: str = Field(min_length=40, max_length=64)
    return_profile: Literal["browser", "desktop-loopback-v1"] = "browser"


class DisableIn(Reviewed):
    # "authorization": stop renewable account sign-in only; "all": also turn
    # off saved connections. Saved connections are never deleted here.
    scope: Literal["authorization", "all"] = "authorization"


def _context(request):
    # An operator overlay or deployment switch changing while the provider
    # consent screen is open also invalidates that authorization transaction.
    loaded, effective = config.load_global_config(), config.load_config()
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Connection configuration is unavailable.")
    values = [context_for(request), [{k: cfg.get(k) for k in ("connections", "oauth", "enterprise")}
                                   for cfg in (loaded, effective)], connections.deployment_override(),
              config.env_flag("MAVERICK_OAUTH_VAULT"), config.env_flag("LIGHTWORK_OAUTH_VAULT"),
              config.env_flag("MAVERICK_OAUTH_DESKTOP_RETURN"), config.env_flag("LIGHTWORK_OAUTH_DESKTOP_RETURN"),
              connection_oauth.desktop_instance_id()]
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def _authority(request, response, payload=None, *, operator=False):
    if operator or has_permission(request, "admin"):
        require_permission(request, "admin")
    else:
        require_permission(request, "operate")
        if not connection_oauth.self_connect_profiles():
            raise HTTPException(403, "Ask an administrator to allow employees to connect approved own accounts in Settings.")
    if operator:
        require_global_permission(request, "admin")
    actor = caller_principal(request)
    if not actor or not actor.startswith("user:") or not current_tenant_id_strict():
        raise HTTPException(403, "Sign in with your named account and select a workspace to connect accounts.")
    response.headers["Cache-Control"] = "private, no-store"
    context = _context(request)
    supplied = payload.context if payload else request.headers.get("X-Lightwork-Connection-Context")
    if supplied is not None and not constant_time_equals(supplied, context):
        raise HTTPException(409, "Account, workspace or deployment settings changed. Reload Connections.")
    if payload is not None:
        from .app import _require_same_origin
        _require_same_origin(request)
        if payload.confirm is not True:
            raise HTTPException(422, "Review and confirm the account connection action.")
    return actor, context


def _callback(request, return_profile="browser"):
    base = str(request.base_url).rstrip("/")
    parsed = urlsplit(base)
    if any(k in request.headers for k in ("x-forwarded-host", "forwarded")):
        # Managed proxies must configure the externally served base correctly;
        # untrusted forwarding headers cannot select a credential return target.
        raise HTTPException(409, "Authorization requires a trusted app return address.")
    if return_profile != "browser":
        if return_profile != connection_oauth.DESKTOP_PROFILE or base != "http://127.0.0.1:8765" or not connection_oauth.desktop_return_enabled():
            raise HTTPException(409, "Desktop authorization requires the enabled local app return profile.")
        return connection_oauth.DESKTOP_CALLBACK
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise HTTPException(409, "Remote account authorization requires HTTPS.")
    return base + "/connections"


def _call(operation):
    try:
        return operation()
    except (PermissionError, ValueError, connections.ConnectionVersionConflict) as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        # Provider responses may contain codes, secrets and account payloads.
        raise HTTPException(503, "Account authorization was not confirmed. Refresh Connections; start a new authorization if needed.") from exc


def _applications(actor, can_manage):
    available = connection_oauth.available_applications(actor)
    if not can_manage:
        return available
    managed = connection_oauth.managed_applications(actor)
    providers = {row["provider"] for row in managed}
    # A personal legacy registration remains usable, but its private revision
    # must never prefill the separate workspace registration editor.
    return managed + [row for row in available if row["provider"] not in providers]


NAMED_SIGN_IN_NEEDED = (
    "Connecting an account by signing in to it needs a named Lightwork sign-in, so each connected "
    "account belongs to a person. Connections that use a key work without it."
)


@router.get("")
def overview(request: Request, response: Response):
    if not str(caller_principal(request) or "").startswith("user:"):
        # Single-user and shared-token installations have no named person to own a
        # renewable account sign-in. Nothing was lost, so answer plainly instead of
        # a 403 the page would read as revoked access. Changing routes still refuse.
        # Only an administrator may inspect this branch; a named employee with
        # approved self-connect access is admitted below by _authority.
        require_permission(request, "admin")
        from .local_owner import available as local_owner_available

        can_set_up = local_owner_available(request)
        response.headers["Cache-Control"] = "private, no-store"
        return {"account_sign_in_available": False, "can_set_up_sign_in": can_set_up,
                "message": NAMED_SIGN_IN_NEEDED + (" You can set up named sign-in now." if can_set_up
                                                  else " Ask whoever manages Lightwork sign-in to set it up.")}
    actor, context = _authority(request, response)
    enabled = connection_oauth.enabled()
    is_admin = has_permission(request, "admin")
    approved = connection_oauth.self_connect_profiles()
    can_manage = has_global_permission(request, "admin")
    return {"context": context, "workspace_context": context_for(request), "can_manage_applications": can_manage,
        "enabled": enabled, "connections_enabled": connections.enabled(), "can_manage_keys": is_admin,
        "desktop_return_enabled": connection_oauth.desktop_return_enabled(),
        "desktop_return_available": bool(connection_oauth.desktop_instance_id()),
        "desktop_callback_uri": connection_oauth.DESKTOP_CALLBACK,
        "callback_uri": _callback(request), "profiles": [{"id": key, **value} for key, value in connection_oauth.PROFILES.items() if is_admin or key in approved],
        "applications": _call(lambda: _applications(actor, can_manage)) if enabled else [],
        "connections": _call(lambda: connections.list_connections(owner=actor)) if connections.enabled() else [],
        "live_provider_verified": False}


@router.post("/enable")
def enable(request: Request, response: Response, payload: Reviewed):
    _authority(request, response, payload, operator=True)
    if connections.deployment_override() is False or any(config.env_flag(name) is False for name in ("MAVERICK_OAUTH_VAULT", "LIGHTWORK_OAUTH_VAULT")):
        raise HTTPException(409, "Deployment policy disables saved account authorization.")
    with settings_store._locked(strict=True):
        _authority(request, response, payload, operator=True)
        data = settings_store._load_overlay_for_update()
        data.setdefault("connections", {})["enable"] = True
        data.setdefault("oauth", {})["vault"] = True
        settings_store._write(data)
    config.reset_config_cache()
    if not connection_oauth.enabled():
        raise HTTPException(409, "Saved account authorization remains blocked by deployment policy.")
    # Activation intentionally changes the configuration portion of context.
    return {"enabled": True, "reload_required": True}


@router.put("/application")
def application(request: Request, response: Response, payload: ApplicationIn):
    actor, _ = _authority(request, response, payload, operator=True)
    _call(lambda: connection_oauth.save_workspace_application(actor, provider=payload.provider, client_id=payload.client_id,
        client_secret=payload.client_secret, expected_revision=payload.expected_revision, desktop_return=payload.desktop_return))
    return overview(request, response)


@router.post("/authorize")
def authorize(request: Request, response: Response, payload: AuthorizeIn):
    actor, context = _authority(request, response, payload)
    callback = _callback(request, payload.return_profile)
    return _call(lambda: connection_oauth.begin(actor, profile=payload.profile, name=payload.name,
        expected_revision=payload.expected_revision, site_url=payload.site_url,
        context=context, redirect_uri=callback, return_profile=payload.return_profile,
        native_handle=payload.native_handle, prepare_ticket=payload.prepare_ticket, self_connect=not has_permission(request, "admin")))


@router.post("/desktop-return/prepare")
def prepare_desktop_return(request: Request, response: Response, payload: NativePrepareIn):
    actor, context = _authority(request, response, payload)
    _callback(request, connection_oauth.DESKTOP_PROFILE)
    if not has_permission(request, "admin") and payload.profile not in connection_oauth.self_connect_profiles():
        raise HTTPException(403, "This account profile is not approved for employee connection.")
    return _call(lambda: connection_oauth.native_prepare_ticket(actor, profile=payload.profile,
        name=payload.name, expected_revision=payload.expected_revision, site_url=payload.site_url,
        context=context))


@router.post("/exchange")
def exchange(request: Request, response: Response, payload: ExchangeIn):
    actor, context = _authority(request, response, payload)
    callback = _callback(request, payload.return_profile)
    record = _call(lambda: connection_oauth.finish(actor, state=payload.state, code=payload.code,
        context=context, redirect_uri=callback, return_profile=payload.return_profile))
    return {"connection": record, "context": context, "live_provider_verified": False}


@router.post("/cancel")
def cancel(request: Request, response: Response, payload: CancelIn):
    actor, context = _authority(request, response, payload)
    callback = _callback(request, payload.return_profile)
    cancelled = _call(lambda: connection_oauth.cancel_consent(actor, state=payload.state,
        context=context, redirect_uri=callback, return_profile=payload.return_profile))
    return {"cancelled": cancelled, "context": context}


@router.post("/desktop-return/enable")
def enable_desktop_return(request: Request, response: Response, payload: Reviewed):
    _authority(request, response, payload, operator=True)
    if any(config.env_flag(name) is False for name in ("MAVERICK_OAUTH_DESKTOP_RETURN", "LIGHTWORK_OAUTH_DESKTOP_RETURN")):
        raise HTTPException(409, "Deployment policy disables desktop account return.")
    with settings_store._locked(strict=True):
        _authority(request, response, payload, operator=True)
        data = settings_store._load_overlay_for_update()
        data.setdefault("oauth", {})["desktop_return"] = True
        settings_store._write(data)
    config.reset_config_cache()
    return {"enabled": connection_oauth.desktop_return_enabled(), "reload_required": True}


def _global_switch(section: str, key: str) -> bool:
    return (config.load_global_config().get(section) or {}).get(key) is True


def _record_off(actor: str, changes: list[tuple[str, str, bool]]) -> None:
    from maverick.audit import EventKind, audit_event

    for section, key, old in changes:
        audit_event(EventKind.SETTING_CHANGED, agent="dashboard", _global=True, actor=actor,
                    section=section, key=key, old=old, new=False, confirmed=True)


def _switch_off(request, response, payload, keys, still_on) -> None:
    """Write ``False`` for each ``(section, key)`` in one locked save, verify it
    took effect and record one audit row per switch that changed. Nothing is
    deleted: saved connections and provider applications stay as they are."""
    actor, _ = _authority(request, response, payload, operator=True)
    with settings_store._locked(strict=True):
        _authority(request, response, payload, operator=True)
        before = settings_store._load_overlay_for_update()
        changes = [(section, key, _global_switch(section, key)) for section, key in keys]
        data = copy.deepcopy(before)
        for section, key in keys:
            table = data.get(section)
            if table is not None and not isinstance(table, dict):
                raise HTTPException(503, "Connection configuration is unavailable. Nothing was changed.")
            data.setdefault(section, {})[key] = False
        settings_store._write(data)
        config.reset_config_cache()
        if still_on():
            settings_store._write(before)
            config.reset_config_cache()
            raise HTTPException(409, "Higher-precedence deployment settings keep this on. Nothing was changed.")
        from maverick.audit import AuditRefused
        try:
            _record_off(actor, [change for change in changes if change[2]])
        except AuditRefused as exc:
            settings_store._write(before)
            config.reset_config_cache()
            raise HTTPException(503, "The change could not be recorded, so it was undone.") from exc


@router.post("/disable")
def disable(request: Request, response: Response, payload: DisableIn):
    """Turn off saved account authorization (and, with scope "all", saved
    connections). Accounts connected here stop working until it is turned on
    again; their encrypted records are kept."""
    _authority(request, response, payload, operator=True)
    if any(config.env_flag(name) is True for name in ("MAVERICK_OAUTH_VAULT", "LIGHTWORK_OAUTH_VAULT")):
        raise HTTPException(409, "Deployment settings keep saved account authorization on, so it can't be turned off here.")
    keys = [("oauth", "vault")]
    if payload.scope == "all":
        if connections.deployment_override() is True:
            raise HTTPException(409, "Deployment settings keep saved connections on, so they can't be turned off here.")
        keys.append(("connections", "enable"))
    _switch_off(request, response, payload, keys,
                lambda: connection_oauth.enabled() or (payload.scope == "all" and connections.enabled()))
    return {"enabled": connection_oauth.enabled(), "connections_enabled": connections.enabled(),
            "reload_required": True}


@router.post("/desktop-return/disable")
def disable_desktop_return(request: Request, response: Response, payload: Reviewed):
    """Stop system-browser sign-in returns to the desktop app. Accounts
    already connected keep working; browser sign-in is unchanged."""
    _authority(request, response, payload, operator=True)
    if any(config.env_flag(name) is True for name in ("MAVERICK_OAUTH_DESKTOP_RETURN", "LIGHTWORK_OAUTH_DESKTOP_RETURN")):
        raise HTTPException(409, "Deployment settings keep desktop account return on, so it can't be turned off here.")
    _switch_off(request, response, payload, [("oauth", "desktop_return")],
                connection_oauth.desktop_return_enabled)
    return {"enabled": connection_oauth.desktop_return_enabled(), "reload_required": True}
