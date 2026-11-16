"""OAuth 2.1 token provider for remote MCP servers (B2).

The static-bearer path (`[mcp_servers.<name>] auth_token`) works when you already
hold a long-lived token. For servers behind an OAuth 2.1 authorization server,
the **client_credentials** grant (machine-to-machine, no user redirect) is
supported: :class:`OAuthTokenProvider` fetches a short-lived access token,
caches it, and refreshes before expiry.

The authorization_code grant (a person signs in through a browser redirect) is
not offered. It needs a step that opens the authorization page, receives the
code and keeps the tokens across restarts, and Lightwork has none for MCP
servers; a server configured with it could only fail to start. The option is
refused at config time and names the choices that work.

The token endpoint call is injectable (`fetch=`) so the provider unit-tests
against a mock endpoint with no network; production uses an https POST.
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
        if grant == "authorization_code":
            raise ValueError(
                "grant_type authorization_code is not available for MCP servers: "
                "Lightwork has no step that completes that sign-in. Use "
                "grant_type client_credentials, or a static auth_token")
        if grant != "client_credentials":
            raise ValueError(
                f"unsupported grant_type {grant!r}; expected client_credentials")
        return cls(
            token_url=token_url,
            client_id=client_id,
            client_secret=str(d.get("client_secret") or ""),
            scope=str(d.get("scope") or ""),
            grant_type=grant,
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
    # plaintext/file scheme.
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

    Thread-safe; ``token()`` is sync.
    """

    def __init__(self, cfg: OAuthConfig, *, fetch=None):
        if cfg.grant_type != "client_credentials":
            raise ValueError("OAuthTokenProvider requires the client_credentials grant")
        self._cfg = cfg
        self._fetch = fetch or _default_fetch
        self._lock = threading.Lock()
        self._access_token: str | None = None
        self._expires_at = 0.0

    def cached_token(self, *, now: float | None = None) -> str | None:
        """The cached access token while it is fresh, else None (no network).

        Never waits: token() holds the lock across the blocking token request,
        and this runs on the event loop, so a busy lock answers None and the
        caller awaits the off-loop token() instead.
        """
        now = time.time() if now is None else now
        if not self._lock.acquire(blocking=False):
            return None
        try:
            if self._access_token and now < self._expires_at - _EXPIRY_SKEW_S:
                return self._access_token
            return None
        finally:
            self._lock.release()

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


def generate_pkce() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` for PKCE S256 (RFC 7636).

    Used by connection sign-in (``oauth_providers``), not by MCP servers.

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


__all__ = [
    "OAuthConfig",
    "OAuthTokenProvider",
    "generate_pkce",
]
