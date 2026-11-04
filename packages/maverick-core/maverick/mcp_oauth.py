"""OAuth 2.1 token providers for remote MCP servers (B2).

The static-bearer path (`[mcp_servers.<name>] auth_token`) works when you already
hold a long-lived token. For servers behind an OAuth 2.1 authorization server,
two grants are supported:

  - **client_credentials** (machine-to-machine, no user redirect) —
    :class:`OAuthTokenProvider` fetches a short-lived access token, caches it,
    and refreshes before expiry.
  - **authorization_code** + PKCE (user-redirect flow) —
    :class:`AuthorizationCodeProvider` builds the authorization URL, exchanges
    the returned code, and refreshes via the refresh_token grant.

The token endpoint call is injectable (`fetch=` / `post=`) so both providers
unit-test against a mock endpoint with no network; production uses an https POST.
The user-redirect leg + real-IdP validation need a live authorization server; the
protocol logic here (PKCE, URL build, exchange, refresh) is unit-tested in
isolation.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

# Refresh this many seconds before the token actually expires, to absorb clock
# skew + request latency.
_EXPIRY_SKEW_S = 60.0
_DEFAULT_TTL_S = 3600.0


@dataclass(frozen=True)
class OAuthConfig:
    token_url: str
    client_id: str
    client_secret: str = ""
    scope: str = ""
    grant_type: str = "client_credentials"
    # authorization_code grant only (user-redirect flow):
    authorize_url: str = ""
    redirect_uri: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> OAuthConfig:
        if not isinstance(d, dict):
            raise ValueError("oauth config must be a table")
        token_url = str(d.get("token_url") or "").strip()
        client_id = str(d.get("client_id") or "").strip()
        if not token_url or not client_id:
            raise ValueError("oauth requires token_url and client_id")
        if not token_url.startswith("https://"):
            raise ValueError(f"oauth token_url must be https://, got {token_url!r}")
        grant = str(d.get("grant_type") or "client_credentials").strip()
        if grant not in ("client_credentials", "authorization_code"):
            raise ValueError(
                "unsupported grant_type "
                f"{grant!r}; expected client_credentials or authorization_code")
        authorize_url = str(d.get("authorize_url") or "").strip()
        redirect_uri = str(d.get("redirect_uri") or "").strip()
        if grant == "authorization_code":
            if not authorize_url or not redirect_uri:
                raise ValueError(
                    "authorization_code grant requires authorize_url and redirect_uri")
            if not authorize_url.startswith("https://"):
                raise ValueError(
                    f"oauth authorize_url must be https://, got {authorize_url!r}")
        return cls(
            token_url=token_url,
            client_id=client_id,
            client_secret=str(d.get("client_secret") or ""),
            scope=str(d.get("scope") or ""),
            grant_type=grant,
            authorize_url=authorize_url,
            redirect_uri=redirect_uri,
        )


def _default_fetch(cfg: OAuthConfig) -> dict:
    """POST the client_credentials grant to the token endpoint. https-only.

    The token_url is operator config (not model-controlled), so an https scheme
    check is the sanity guard here — same posture as the MCP server `url`."""
    import json
    import urllib.parse
    import urllib.request
    # token_url is https-validated in from_dict, but OAuthConfig is directly
    # constructable too -- re-check here so this sink is never reached with a
    # plaintext/file scheme, matching _default_token_post.
    if not cfg.token_url.startswith("https://"):
        raise ValueError(f"oauth token_url must be https://, got {cfg.token_url!r}")
    data = {"grant_type": cfg.grant_type, "client_id": cfg.client_id}
    if cfg.client_secret:
        data["client_secret"] = cfg.client_secret
    if cfg.scope:
        data["scope"] = cfg.scope
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        cfg.token_url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 -- https-checked
        return json.loads(r.read(100_000).decode("utf-8"))


class OAuthTokenProvider:
    """Cache + refresh a client-credentials OAuth access token.

    Thread-safe; ``token()`` is sync. Authorization-code configurations must use
    :class:`AuthorizationCodeProvider` so the code, redirect URI, and PKCE
    verifier are sent during token exchange.
    """

    def __init__(self, cfg: OAuthConfig, *, fetch=None):
        if cfg.grant_type != "client_credentials":
            raise ValueError("OAuthTokenProvider requires the client_credentials grant")
        self._cfg = cfg
        self._fetch = fetch or _default_fetch
        self._lock = threading.Lock()
        self._access_token: str | None = None
        self._expires_at = 0.0

    def token(self, *, now: float | None = None) -> str:
        """Return a valid access token, fetching/refreshing if needed."""
        now = time.time() if now is None else now
        with self._lock:
            if self._access_token and now < self._expires_at - _EXPIRY_SKEW_S:
                return self._access_token
            resp = self._fetch(self._cfg)
            if not isinstance(resp, dict) or not resp.get("access_token"):
                raise ValueError(
                    "oauth token endpoint did not return an access_token")
            self._access_token = str(resp["access_token"])
            try:
                ttl = float(resp.get("expires_in", _DEFAULT_TTL_S))
            except (TypeError, ValueError):
                ttl = _DEFAULT_TTL_S
            self._expires_at = now + max(0.0, ttl)
            return self._access_token


# --- Authorization-code grant (user-redirect flow, OAuth 2.1 + PKCE) ---------
# client_credentials is machine-to-machine; this is the path for MCP servers
# that authorize on behalf of a *user*. The browser redirect + real-IdP
# validation need a live authorization server, but every piece of protocol
# logic below (PKCE, the authorization URL, the code exchange, refresh) is pure
# and unit-tested with an injected token endpoint.


def generate_pkce() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` for PKCE S256 (RFC 7636).

    The verifier is the secret kept by the client; the challenge is sent in the
    authorization request and re-derived by the server from the verifier at
    token-exchange time, so an intercepted authorization code is useless without
    the verifier."""
    import base64
    import hashlib
    import secrets

    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def build_authorization_url(
    cfg: OAuthConfig, *, code_challenge: str, state: str,
    code_challenge_method: str = "S256",
) -> str:
    """The URL the user opens to authorize (PKCE authorization request)."""
    import urllib.parse

    if cfg.grant_type != "authorization_code":
        raise ValueError("authorization URL requires the authorization_code grant")
    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "state": state,
    }
    if cfg.scope:
        params["scope"] = cfg.scope
    sep = "&" if "?" in cfg.authorize_url else "?"
    return cfg.authorize_url + sep + urllib.parse.urlencode(params)


def _default_token_post(token_url: str, data: dict) -> dict:
    """POST form-encoded ``data`` to the token endpoint. https-only."""
    import json
    import urllib.parse
    import urllib.request

    if not token_url.startswith("https://"):
        raise ValueError(f"oauth token_url must be https://, got {token_url!r}")
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        token_url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 -- https-checked
        return json.loads(r.read(100_000).decode("utf-8"))


class AuthorizationCodeProvider:
    """Authorization-code-grant token provider with PKCE + refresh.

    Flow: ``start()`` -> open the URL, user authorizes, the IdP redirects back
    with ``code`` + ``state`` -> ``complete(code, verifier)`` exchanges it for
    tokens. After that ``token()`` returns a valid access token, refreshing via
    the refresh_token grant before expiry. Thread-safe. ``post`` is injectable
    (``(token_url, data) -> dict``) so the exchange + refresh unit-test offline.
    """

    def __init__(self, cfg: OAuthConfig, *, post=None):
        if cfg.grant_type != "authorization_code":
            raise ValueError("AuthorizationCodeProvider requires the authorization_code grant")
        self._cfg = cfg
        self._post = post or _default_token_post
        self._lock = threading.Lock()
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._expires_at = 0.0

    def start(self) -> tuple[str, str, str]:
        """Begin the redirect flow. Returns ``(authorization_url, state,
        code_verifier)``; keep ``state`` + ``code_verifier`` to validate the
        callback and complete the exchange."""
        import secrets

        verifier, challenge = generate_pkce()
        state = secrets.token_urlsafe(16)
        url = build_authorization_url(self._cfg, code_challenge=challenge, state=state)
        return url, state, verifier

    def complete(self, code: str, code_verifier: str, *, now: float | None = None) -> str:
        """Exchange an authorization ``code`` (+ PKCE verifier) for tokens."""
        now = time.time() if now is None else now
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._cfg.redirect_uri,
            "client_id": self._cfg.client_id,
            "code_verifier": code_verifier,
        }
        if self._cfg.client_secret:
            data["client_secret"] = self._cfg.client_secret
        resp = self._post(self._cfg.token_url, data)
        with self._lock:
            return self._store(resp, now=now)

    def token(self, *, now: float | None = None) -> str:
        """A valid access token, refreshing via the refresh_token grant when
        near expiry. Raises if the flow hasn't been completed yet."""
        now = time.time() if now is None else now
        with self._lock:
            if self._access_token and now < self._expires_at - _EXPIRY_SKEW_S:
                return self._access_token
            if not self._refresh_token:
                if self._access_token:
                    return self._access_token  # no refresh available; use until it 401s
                raise ValueError(
                    "not authorized: call complete() with an authorization code first")
            data = {
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
                "client_id": self._cfg.client_id,
            }
            if self._cfg.client_secret:
                data["client_secret"] = self._cfg.client_secret
            return self._store(self._post(self._cfg.token_url, data), now=now)

    def _store(self, resp: dict, *, now: float) -> str:
        if not isinstance(resp, dict) or not resp.get("access_token"):
            raise ValueError("oauth token endpoint did not return an access_token")
        self._access_token = str(resp["access_token"])
        rt = resp.get("refresh_token")
        if rt:  # a refresh response may omit it -> keep the prior one
            self._refresh_token = str(rt)
        try:
            ttl = float(resp.get("expires_in", _DEFAULT_TTL_S))
        except (TypeError, ValueError):
            ttl = _DEFAULT_TTL_S
        self._expires_at = now + max(0.0, ttl)
        return self._access_token


__all__ = [
    "OAuthConfig",
    "OAuthTokenProvider",
    "AuthorizationCodeProvider",
    "generate_pkce",
    "build_authorization_url",
]
