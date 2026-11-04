"""OAuth provider presets -- the turnkey "connect this account" registry.

The vault (:mod:`maverick.oauth_vault`) and the OAuth helpers are deliberately
provider-agnostic: every endpoint is supplied per call. That is correct for a
library but a chore for an operator, who then has to hand-enter Slack's or
Google's authorize/token URLs and scopes. This registry supplies the well-known
endpoints + default scopes for the major SaaS providers, so an account is
connected by NAME -- pick ``slack``, authorize, done -- and the vault's refresher
is built automatically from the preset.

Secrets discipline is unchanged: the client id/secret come from the operator's
own environment (``<PROVIDER>_OAUTH_CLIENT_ID`` / ``..._SECRET`` by default) and
are never persisted in a trigger or the registry; only the resulting token is
sealed in the per-tenant vault. Additive and extensible via :func:`register`.
"""
from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class OAuthProvider:
    """A well-known OAuth2 provider's endpoints + sensible default scopes.

    ``client_id_env`` / ``client_secret_env`` name the environment variables the
    operator sets with their app credentials (an OAuth *client* is per-install,
    so it can't ship in the preset). ``scopes`` is the default consent set; a
    connect call may override it."""

    name: str
    authorize_url: str
    token_url: str
    label: str = ""
    scopes: tuple[str, ...] = ()
    client_id_env: str = ""
    client_secret_env: str = ""
    # Some providers (Google, Microsoft) only return a refresh_token when these
    # are present on the authorize request; folded in when set.
    extra_authorize_params: dict = field(default_factory=dict)

    def default_client_id_env(self) -> str:
        return self.client_id_env or f"{self.name.upper()}_OAUTH_CLIENT_ID"

    def default_client_secret_env(self) -> str:
        return self.client_secret_env or f"{self.name.upper()}_OAUTH_CLIENT_SECRET"


_PROVIDERS: dict[str, OAuthProvider] = {}


def register(provider: OAuthProvider) -> None:
    """Register (or override) a provider preset by name."""
    _PROVIDERS[provider.name] = provider


def get_provider(name: str) -> OAuthProvider | None:
    return _PROVIDERS.get(str(name or "").strip().lower())


def available_providers() -> list[str]:
    return sorted(_PROVIDERS)


def provider_catalog() -> list[dict]:
    """Presets for the dashboard connect UI -- names/labels/scopes and the env
    var names to set. Never includes any secret value."""
    out = []
    for name in available_providers():
        p = _PROVIDERS[name]
        out.append({
            "name": p.name,
            "label": p.label or p.name.title(),
            "scopes": list(p.scopes),
            "client_id_env": p.default_client_id_env(),
            "client_secret_env": p.default_client_secret_env(),
        })
    return out


def _client_id(provider: OAuthProvider, client_id: str = "") -> str:
    return (client_id or os.environ.get(provider.default_client_id_env(), "")).strip()


def make_refresher(name: str, *, client_id: str = "",
                   client_secret_env: str = "") -> Callable[[dict], dict] | None:
    """Build a vault ``refresher(record) -> token_dict`` for a preset provider.

    Returns ``None`` for an unknown provider or when no client id is available
    (nothing to refresh with). The client secret is read from the environment at
    refresh time -- never captured here."""
    provider = get_provider(name)
    if provider is None:
        return None
    cid = _client_id(provider, client_id)
    if not cid:
        return None
    secret_env = client_secret_env or provider.default_client_secret_env()

    def _refresh(record: dict) -> dict:
        from .tools.oauth_helper import _post_form  # https + SSRF-guarded POST
        data = {
            "grant_type": "refresh_token",
            "client_id": cid,
            "refresh_token": str((record or {}).get("refresh_token") or ""),
        }
        secret = os.environ.get(secret_env, "")
        if secret:
            data["client_secret"] = secret
        return _post_form(provider.token_url, data)

    return _refresh


def build_authorize_url(name: str, *, redirect_uri: str, client_id: str = "",
                        state: str = "", scopes=None) -> tuple[str, str] | None:
    """Return ``(authorize_url, pkce_verifier)`` for a preset provider, or
    ``None`` if unknown / no client id. Keep the verifier for :func:`exchange_code`.
    PKCE S256 is always used."""
    provider = get_provider(name)
    if provider is None:
        return None
    cid = _client_id(provider, client_id)
    if not cid:
        return None
    from urllib.parse import urlencode

    from .mcp_oauth import generate_pkce
    verifier, challenge = generate_pkce()
    params = {
        "response_type": "code",
        "client_id": cid,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    scope_list = list(scopes) if scopes else list(provider.scopes)
    if scope_list:
        params["scope"] = " ".join(scope_list)
    if state:
        params["state"] = state
    params.update(provider.extra_authorize_params)
    return f"{provider.authorize_url}?{urlencode(params)}", verifier


def exchange_code(name: str, *, code: str, redirect_uri: str, verifier: str = "",
                  client_id: str = "", client_secret_env: str = "") -> dict:
    """Exchange an authorization code for tokens at the preset token endpoint and
    seal the result in the per-tenant vault under the provider name. Returns a
    redacted summary (never the raw token). Raises on failure."""
    provider = get_provider(name)
    if provider is None:
        raise ValueError(f"unknown OAuth provider {name!r}")
    cid = _client_id(provider, client_id)
    if not cid:
        raise ValueError(f"set {provider.default_client_id_env()} to connect {name}")
    from .tools.oauth_helper import _post_form
    data = {
        "grant_type": "authorization_code",
        "client_id": cid,
        "code": str(code),
        "redirect_uri": redirect_uri,
    }
    if verifier:
        data["code_verifier"] = verifier
    secret = os.environ.get(client_secret_env or provider.default_client_secret_env(), "")
    if secret:
        data["client_secret"] = secret
    resp = _post_form(provider.token_url, data)
    if not resp.get("access_token"):
        raise ValueError("no access_token in the provider's token response")
    from .oauth_vault import get_vault
    get_vault().put(provider.name, resp)
    return {
        "provider": provider.name,
        "token_type": resp.get("token_type", ""),
        "expires_in": resp.get("expires_in"),
        "scope": resp.get("scope", ""),
        "has_refresh_token": bool(resp.get("refresh_token")),
    }


# ---- seed the major providers ----------------------------------------------
# Endpoints are the providers' documented OAuth2 authorize/token URLs; scopes are
# a sensible read-first default the operator can override at connect time.

register(OAuthProvider(
    "google", "https://accounts.google.com/o/oauth2/v2/auth",
    "https://oauth2.googleapis.com/token", label="Google",
    scopes=("openid", "email", "https://www.googleapis.com/auth/gmail.readonly"),
    # Google only returns a refresh_token with these on the consent request.
    extra_authorize_params={"access_type": "offline", "prompt": "consent"},
))
register(OAuthProvider(
    "microsoft", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "https://login.microsoftonline.com/common/oauth2/v2.0/token", label="Microsoft 365",
    scopes=("offline_access", "User.Read", "Mail.Read"),
))
register(OAuthProvider(
    "slack", "https://slack.com/oauth/v2/authorize",
    "https://slack.com/api/oauth.v2.access", label="Slack",
    scopes=("channels:read", "chat:write"),
))
register(OAuthProvider(
    "github", "https://github.com/login/oauth/authorize",
    "https://github.com/login/oauth/access_token", label="GitHub",
    scopes=("repo", "read:org"),
))
register(OAuthProvider(
    "hubspot", "https://app.hubspot.com/oauth/authorize",
    "https://api.hubapi.com/oauth/v1/token", label="HubSpot",
    scopes=("crm.objects.contacts.read",),
))
register(OAuthProvider(
    "salesforce", "https://login.salesforce.com/services/oauth2/authorize",
    "https://login.salesforce.com/services/oauth2/token", label="Salesforce",
    scopes=("api", "refresh_token"),
))
register(OAuthProvider(
    "zoom", "https://zoom.us/oauth/authorize",
    "https://zoom.us/oauth/token", label="Zoom",
    scopes=("meeting:read",),
))
register(OAuthProvider(
    "atlassian", "https://auth.atlassian.com/authorize",
    "https://auth.atlassian.com/oauth/token", label="Atlassian (Jira/Confluence)",
    scopes=("read:jira-work", "offline_access"),
    extra_authorize_params={"audience": "api.atlassian.com", "prompt": "consent"},
))
register(OAuthProvider(
    "linear", "https://linear.app/oauth/authorize",
    "https://api.linear.app/oauth/token", label="Linear",
    scopes=("read",),
))
# (Zendesk et al. are per-install-subdomain providers -- their endpoints embed a
# tenant subdomain, which a static preset can't supply -- so they're left out of
# the turnkey seed rather than shipped with an unsubstitutable placeholder host.)


__all__ = [
    "OAuthProvider", "register", "get_provider", "available_providers",
    "provider_catalog", "make_refresher", "build_authorize_url", "exchange_code",
]
