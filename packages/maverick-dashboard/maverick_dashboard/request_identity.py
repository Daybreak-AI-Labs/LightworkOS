"""Verified dashboard caller identity and attributable durable-write actor."""
from __future__ import annotations

import hashlib
import os

from fastapi import HTTPException, Request

from .auth import constant_time_equals


def privacy_auth_genuinely_off(*, dashboard_token=None) -> bool:
    """Strict auth-off decision for privacy credential and mutation boundaries."""
    if dashboard_token is None:
        from ._shared import dashboard_token
    if dashboard_token():
        return False
    try:
        from maverick.config import config_source_errors, load_config

        config = load_config() or {}
        if config_source_errors():
            return False
    except Exception:
        return False
    if not isinstance(config, dict):
        return False

    def _env_override(name: str) -> bool | None:
        raw = os.environ.get(name)
        if raw is None or not raw.strip():
            return None
        value = raw.strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
        if value in {"0", "false", "no", "off"}:
            return False
        # Invalid auth policy is uncertainty, never permission to use ambient
        # credentials or mint an unattributed privacy mutation.
        return True

    dashboard = config.get("dashboard") or {}
    auth = config.get("auth") or {}
    if not isinstance(dashboard, dict) or not isinstance(auth, dict):
        return False

    configured = []
    for env_name, section_value in (
        ("MAVERICK_DASHBOARD_REQUIRE_AUTH", dashboard.get("require_auth", False)),
        ("MAVERICK_DASHBOARD_INVITES", dashboard.get("invites", False)),
    ):
        override = _env_override(env_name)
        if override is None:
            if not isinstance(section_value, bool):
                return False
            configured.append(section_value)
        else:
            configured.append(override)

    oidc = auth.get("oidc") or {}
    proxy = auth.get("proxy") or {}
    saml = auth.get("saml") or {}
    if not all(isinstance(section, dict) for section in (oidc, proxy, saml)):
        return False
    for env_name, section in (
        ("MAVERICK_OIDC_ENABLED", oidc),
        ("MAVERICK_PROXY_AUTH", proxy),
    ):
        override = _env_override(env_name)
        if override is None:
            enabled = section.get("enabled", False)
            if not isinstance(enabled, bool):
                return False
            configured.append(enabled)
        else:
            configured.append(override)
    # SAML has no enable flag: any configured surface is an auth mechanism;
    # a partial section is still uncertainty and therefore denies ambient use.
    configured.append(bool(saml))
    return not any(configured)


def request_identity(request: Request, *, caller=None, dashboard_token=None, auth_off=None) -> str | None:
    """Verified identity; ``None`` only in genuine local auth-off mode."""
    if caller is None:
        from .auth import caller_principal as caller
    if dashboard_token is None:
        from ._shared import dashboard_token
    principal = str(caller(request) or "")
    if principal:
        return principal
    expected = dashboard_token()
    if expected:
        authorization = request.headers.get("authorization", "")
        supplied = authorization[7:] if authorization.startswith("Bearer ") else ""
        if supplied and constant_time_equals(supplied, expected):
            return "auth:dashboard-token"
        raise HTTPException(
            status_code=401,
            detail="authenticated caller identity required",
        )
    auth_disabled = auth_off() if auth_off is not None else privacy_auth_genuinely_off(dashboard_token=dashboard_token)
    if auth_disabled:
        return None
    raise HTTPException(
        status_code=401,
        detail="authenticated caller identity required",
    )


def request_actor(request: Request, *, identity=None) -> str:
    """Stable attributable actor for dashboard-originated durable writes."""
    identity = (identity or request_identity)(request) or "local:dashboard"
    if len(identity) <= 256:
        return identity
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"{identity[:183]}#sha256:{digest}"



def document_source_principal(request: Request, *, identity=None) -> str | None:
    """Resolve a verified connector identity, rejecting values too long for grants."""
    principal = (identity or request_identity)(request)
    if principal is not None and len(principal) > 256:
        raise HTTPException(
            status_code=403,
            detail="authenticated principal is too long for connection grants",
        )
    return principal
