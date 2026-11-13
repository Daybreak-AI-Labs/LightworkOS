"""Built-in OIDC authorization-code browser-login flow for the dashboard.

This is the self-contained alternative to the reverse-proxy SSO path
(:mod:`maverick.proxy_auth`): a deployment that can't run an auth proxy in front
of the dashboard gets browser SSO directly, by having the dashboard itself drive
the OAuth2 / OpenID-Connect authorization-code flow.

It is **off by default and fail-closed**: every route here first checks
:func:`maverick.oidc.login_enabled` and returns 404 when the flow isn't fully
configured, so an unconfigured deployment behaves exactly as before (the bearer
gate and the reverse-proxy path are untouched). Configuration lives in
``[auth.oidc]`` (``client_id``/``client_secret``/``redirect_uri``/
``session_secret`` + issuer-or-endpoints); see :func:`maverick.oidc.login_enabled`.

Security mechanics (these are the whole point — see the security checklist in
the PR):

- **CSRF on the callback** via an opaque ``state`` minted at ``/auth/login``,
  stashed in a short-TTL signed transaction cookie, and required to match the
  ``state`` query param on ``/auth/callback`` before any token exchange.
- **PKCE (S256)**: a ``code_verifier`` is generated at login, its S256
  ``code_challenge`` is sent on the authorization request, and the verifier is
  sent on the token exchange — so an intercepted ``code`` can't be redeemed.
- **One-time login transactions**: the callback consumes each signed
  transaction ID server-side before token exchange, preventing replay of a
  captured transaction cookie.
- **Async HTTPS-only token exchange**: the token endpoint must be ``https://`` or we
  refuse to POST the client secret to it, and the network call uses
  ``httpx.AsyncClient`` so failed IdP calls do not block the event loop.
- **ID-token verification reuses** :func:`maverick.oidc.verify_oidc_token` — we
  do not re-implement JWT verification.
- **Open-redirect defence**: ``return_to`` is only honored if it is a safe local
  path; anything external / protocol-relative / with a backslash or control
  char falls back to ``/``.
- **No secrets in logs**: failures log a generic reason only — never the token,
  the authorization code, the client secret, or the session value.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import math
import os
import secrets
import time
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from maverick.oidc import (
    OIDCError,
    VerifiedPrincipal,
    load_oidc_config,
    login_enabled,
    resolve_endpoints,
    verify_oidc_token,
)
from maverick.web_session import sign_session, verify_session

log = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])

# Cookie names.
TX_COOKIE = "mvk_oidc_tx"          # short-lived login transaction (state+PKCE)
SESSION_COOKIE = "mvk_session"     # the authenticated browser session

# Lifetimes (seconds).
_TX_TTL = 600                      # 10 min to complete the round-trip
_SESSION_TTL = 12 * 3600          # 12 h authenticated session

# Per-process replay guard for transaction cookies. The signed cookie remains
# the source of transaction data, but the opaque tx id must be consumed exactly
# once before any token exchange is attempted.
#
# This in-process dict is the guard for a single-replica deployment. In a
# multi-replica HA deployment (the dashboard scaled out behind a load balancer)
# it is NOT sufficient on its own: a captured callback replayed against a
# DIFFERENT replica would not be seen as consumed, so the replay would proceed.
# When a SHARED world-model backend is configured (Postgres), we therefore
# consume the tx id in that shared store instead -- see ``_consume_tx_once`` --
# so the guard is cluster-wide. The in-process dict stays the fallback for the
# default single-process / SQLite deployment, where it is already correct.
_CONSUMED_TX_IDS: dict[str, int] = {}
_CONSUMED_TX_LOCK = asyncio.Lock()

# Synthetic "channel" under which OIDC login transactions are recorded in the
# shared world-model dedup table (``processed_messages``), reusing its proven,
# backend-agnostic first-writer-wins UNIQUE-insert primitive. Namespaced so it
# can never collide with a real messaging channel's external ids.
_OIDC_TX_CHANNEL = "__oidc_login_tx__"

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "testclient"})


def _now() -> int:
    return int(time.time())


def _is_loopback_request(request: Request) -> bool:
    """True when the request's peer is loopback/in-process.

    Used only to decide the cookie ``Secure`` flag: on a real (non-loopback)
    deployment cookies are marked ``Secure`` so they're never sent over plain
    HTTP; loopback dev over http would otherwise never receive them back.
    """
    host = request.client.host if request.client else ""
    return host in _LOOPBACK_HOSTS


def _request_is_https(request: Request) -> bool:
    """True when the browser reached us over TLS, directly or via a
    TLS-terminating reverse proxy (``X-Forwarded-Proto: https``). A proxy
    connects to the app over loopback, so the peer being loopback does NOT
    imply the user is on plain HTTP."""
    if request.url.scheme == "https":
        return True
    forwarded = request.headers.get("x-forwarded-proto", "")
    return forwarded.split(",")[0].strip().lower() == "https"


def _cookie_secure(request: Request) -> bool:
    """Whether to set ``Secure`` on the auth cookies.

    Secure whenever the request arrived over TLS (so a session established
    behind a TLS-terminating proxy that connects over loopback is NOT issued a
    non-Secure cookie that could then leak over a downgraded HTTP request), and
    on any genuinely non-loopback deployment. Only a plain-HTTP loopback dev
    session omits it, so ``http://localhost`` still receives the cookie back.
    """
    return _request_is_https(request) or not _is_loopback_request(request)


def _is_safe_return_to(value: str | None) -> bool:
    """Whether ``value`` is a safe *local* path to redirect a browser to.

    Blocks the open-redirect class: must start with a single ``/`` (a local
    absolute path), must NOT start with ``//`` (protocol-relative -> off-site),
    must contain no backslash (``/\\evil.com`` is treated as ``//`` by some
    browsers) and no control characters (CR/LF/NUL header-splitting tricks).
    """
    if not isinstance(value, str) or not value:
        return False
    if not value.startswith("/"):
        return False
    if value.startswith("//"):
        return False
    if "\\" in value:
        return False
    return all(ord(c) >= 0x20 and c != "\x7f" for c in value)


def _safe_return_to(value: str | None) -> str:
    """Sanitize ``return_to`` to a safe local path, defaulting to ``/``."""
    return value if _is_safe_return_to(value) else "/"


def _code_challenge_s256(verifier: str) -> str:
    """The S256 PKCE code_challenge for ``verifier`` (b64url, no padding)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _shared_release_tx(tx_id: str) -> None:
    """Release a shared-store OIDC transaction claim after a failed login.

    The shared replay guard claims a transaction before token exchange so
    cross-replica replays cannot race that exchange. If the exchange or token
    validation fails, no session was created, so keeping a durable claim only
    creates unauthenticated database growth. Best-effort release preserves the
    HA replay guard for successful logins while bounding failed-flow storage to
    the lifetime of the failed request.
    """
    if not tx_id:
        return
    try:
        from maverick.world_model_backends import is_postgres_configured

        if not is_postgres_configured():
            return
        from ._shared import _world
        world = _world()
        release = getattr(world, "release_processed_message", None)
        if callable(release):
            release(_OIDC_TX_CHANNEL, tx_id)
    except Exception:  # pragma: no cover - cleanup must never mask login failure
        log.warning("OIDC replay guard: shared tx cleanup failed")

def _shared_consume_tx(tx_id: str) -> bool | None:
    """Consume ``tx_id`` in the shared world-model store, if one is configured.

    Returns True on first-consume (proceed), False on replay (reject), or None
    when there is no shared backend / the store is unavailable -- in which case
    the caller falls back to the in-process guard. Runs only when a Postgres
    backend is configured: that is the multi-replica HA case where the
    in-process dict alone leaves a replay window across replicas. Reuses the
    backend-agnostic ``mark_message_processed`` (a UNIQUE-constrained insert that
    returns True exactly once per id, atomically, on both SQLite and Postgres).

    Synchronous and quick (one indexed insert); called from the async callback
    via ``run_in_executor`` so it never blocks the event loop on the DB round
    trip. Any failure returns None (fall back) rather than raising -- a degraded
    shared store must not harden into a hard login outage, and the signed
    cookie + PKCE + state CSRF remain in force regardless.
    """
    try:
        from maverick.world_model_backends import is_postgres_configured
        if not is_postgres_configured():
            return None
        from ._shared import _world
        world = _world()
        # True == first writer (not previously consumed) -> allow this callback.
        return bool(world.mark_message_processed(_OIDC_TX_CHANNEL, tx_id))
    except Exception:  # pragma: no cover - shared store must never gate login hard
        log.warning("OIDC replay guard: shared store unavailable, using in-process guard")
        return None


async def _consume_tx_once(tx_id: str, expires_at: int) -> bool:
    """Atomically mark an OIDC login transaction as consumed.

    Transaction cookies are self-contained so they can survive redirects without
    external session middleware, but callbacks must not be replayable. This
    records the opaque transaction id before the token exchange; repeated
    callbacks with the same cookie are rejected before making an outbound IdP
    request.

    Shared-store first: when a Postgres backend is configured (HA / multi-replica
    dashboard), the id is consumed in that shared store so the guard holds across
    every replica -- the in-process dict alone would let a replay land on a
    sibling replica. Falls back to the in-process guard for the default
    single-process / SQLite deployment, or if the shared store is unavailable.
    """
    if not tx_id:
        return False

    shared = await asyncio.get_running_loop().run_in_executor(
        None, _shared_consume_tx, tx_id
    )
    if shared is not None:
        return shared

    now = _now()
    async with _CONSUMED_TX_LOCK:
        expired = [key for key, exp in _CONSUMED_TX_IDS.items() if exp <= now]
        for key in expired:
            _CONSUMED_TX_IDS.pop(key, None)

        if tx_id in _CONSUMED_TX_IDS:
            return False

        _CONSUMED_TX_IDS[tx_id] = max(expires_at, now + 1)
        return True


async def _exchange_code_for_tokens(
    token_endpoint: str, *, cfg, code: str, code_verifier: str
) -> dict:
    """Exchange an authorization code without blocking the event loop."""
    # Keep the outbound HTTP stack off the dashboard's default import path.
    # OIDC login is optional, and importing the route must remain side-effect
    # free when the feature is disabled.
    import httpx
    from maverick.governed_http import admit_client_request

    async with httpx.AsyncClient(timeout=10.0) as client:
        admit_client_request(client, token_endpoint)
        token_resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": cfg.redirect_uri,
                "client_id": cfg.client_id,
                "code_verifier": code_verifier,
            },
            auth=(cfg.client_id, cfg.client_secret),
        )
    token_resp.raise_for_status()
    token_data = token_resp.json()
    return token_data if isinstance(token_data, dict) else {}


def _set_cookie(response, name: str, value: str, *, max_age: int, secure: bool) -> None:
    """Set a hardened cookie: httponly + samesite=lax (+ secure when not loopback).

    ``samesite=lax`` lets the cookie ride the top-level GET redirect back from
    the IdP (the callback) while still blocking it on cross-site subrequests;
    ``httponly`` keeps it out of ``document.cookie`` (XSS can't read it).
    """
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
    )


def _clear_cookie(response, name: str) -> None:
    response.delete_cookie(name, path="/")


def _principal_from_request_session(request: Request):
    """Return a :class:`VerifiedPrincipal` for a valid ``mvk_session`` cookie.

    Shared with the auth dependency so the session-cookie identity is established
    in exactly one place. Returns ``None`` when login is disabled, the cookie is
    absent, or the cookie fails verification (tampered/expired/wrong-secret).
    """
    if not login_enabled():
        try:
            from .saml import saml_enabled

            if not saml_enabled():
                return None
        except Exception:  # pragma: no cover - unavailable SAML is not a session
            return None
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    cfg = load_oidc_config()
    if not cfg.session_secret:
        return None
    payload = verify_session(raw, cfg.session_secret)
    if not payload:
        return None
    from maverick.oidc import validate_subject
    try:
        sub = validate_subject(payload.get("sub"))
    except ValueError:
        return None
    # Revocation: a session minted before the principal's revocation epoch
    # ("log out everywhere" / SCIM deprovision) is rejected even though its HMAC
    # signature and exp are still valid.
    from .session_revocation import is_revoked
    if is_revoked(sub, payload.get("iat")):
        return None
    claims = session_claims(payload, request, via="session")
    if claims is None:
        return None
    return VerifiedPrincipal(sub=sub, issuer="oidc-session", audience="", claims=claims)


def session_claims(payload: dict, request: Request, *, via: str) -> dict | None:
    """Claims for a verified session cookie, or ``None`` when the session was
    ended on the Sessions page (or its record cannot be read: fail closed).

    A cookie carrying a ``sid`` must be an active row in
    :mod:`session_registry`; its ``mfa``/``mfa_at`` come from that record's
    minting, not from the cookie alone. A cookie without a ``sid`` predates
    session tracking and is accepted, unverified for a second factor, until
    it expires."""
    sid = payload.get("sid")
    claims: dict = {"via": via, "mfa": False, "mfa_at": None, "sid": ""}
    # A workspace invitation needs the email asserted for THIS signed session.
    # The subject directory retains historical aliases and cannot prove which
    # address the provider asserted at the current login.
    idp_email = _normalized_invite_email(payload.get("idp_email"))
    if via == "session" and idp_email:
        claims["idp_email"] = idp_email
    # The address that saved-source permissions match is kept apart from the invitation address.
    verified_email = _normalized_invite_email(payload.get("verified_email"))
    if via == "session" and verified_email:
        claims["verified_email"] = verified_email
    if not isinstance(sid, str) or not sid:
        from .session_policy import company_ttl, idle_minutes

        try:
            if idle_minutes():
                return None  # Legacy cookies cannot establish current activity.
            if via == "session" and _now() >= float(payload["iat"]) + company_ttl(_SESSION_TTL):
                return None
        except (KeyError, TypeError, ValueError, OSError):
            return None
        return claims
    from . import session_registry

    try:
        record = session_registry.current(sid, principal=f"user:{payload.get('sub')}")
        if record is None:
            return None
    except session_registry.SessionStoreError:
        return None
    client = getattr(request, "client", None)
    session_registry.touch(
        sid, ip=str(getattr(client, "host", "") or ""),
        user_agent=request.headers.get("user-agent", ""),
    )
    claims["sid"] = sid
    if payload.get("mfa") is True:
        claims["mfa"] = True
        claims["mfa_at"] = payload.get("mfa_at", payload.get("iat"))
    return claims


def _normalized_invite_email(value: object) -> str:
    """A provider-asserted email suitable for matching a workspace invite."""
    if not isinstance(value, str):
        return ""
    email = value.strip().casefold()
    return email if 3 <= len(email) <= 254 and "@" in email and not any(c.isspace() for c in email) else ""


def _oidc_invite_email(claims: dict) -> str:
    """Keep the current login's signed address, never a historical alias."""
    if claims.get("email_verified") is False:
        return ""
    for key in ("email", "upn", "preferred_username", "sub"):
        email = _normalized_invite_email(claims.get(key))
        if email:
            return email
    return ""


def _oidc_permission_email(claims: dict) -> str:
    """The address a saved-source permission may match: only the email claim, and only when the provider
    asserts that it is verified. A username, UPN or subject is never an address the person has proved."""
    if claims.get("email_verified") is not True:
        return ""
    return _normalized_invite_email(claims.get("email"))


_AUTH_TIME_SKEW = 120  # seconds the provider's clock may run ahead of ours


def credible_auth_time(value: object, *, now: float) -> float | None:
    """When the provider says the person authenticated (OIDC ``auth_time`` /
    SAML ``AuthnInstant`` as an epoch), or ``None`` when it is absent, not a
    number, or from the future beyond clock skew. Never later than ``now``."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        when = float(value)
    except ValueError:
        return None
    if not math.isfinite(when) or when <= 0 or when > now + _AUTH_TIME_SKEW:
        return None
    return min(when, float(now))


def mint_browser_session(request: Request, *, sub: str, secret: str, via: str, mfa: bool,
                         ttl: int, extra: dict | None = None,
                         mfa_at: float | None = None) -> str:
    """Sign a session cookie and record it in :mod:`session_registry`.

    One place for every sign-in flow (OIDC, SAML, invitation, owner), so each
    session carries the same ``sid``/``mfa``/``mfa_at`` fields and appears on
    the Sessions page. ``mfa_at`` is when the provider says the second factor
    happened (``auth_time``); without it the second factor is dated now. A
    record that cannot be written refuses the sign-in
    (:class:`session_registry.SessionStoreError`): a session nobody can list
    or end is not one Lightwork should issue."""
    from . import session_registry

    now = _now()
    sid = session_registry.new_sid()
    if mfa_at is None:
        mfa_at = now
    payload = {"sub": sub, "iat": now, "exp": now + ttl, "sid": sid, "mfa": bool(mfa)}
    if mfa:
        payload["mfa_at"] = mfa_at
    if extra:
        payload.update(extra)
    client = getattr(request, "client", None)
    session_registry.register(
        sid=sid, principal=f"user:{sub}", via=via, mfa=bool(mfa),
        mfa_at=float(mfa_at) if mfa else None, issued_at=now, expires_at=now + ttl,
        ip=str(getattr(client, "host", "") or ""),
        user_agent=request.headers.get("user-agent", ""),
    )
    return sign_session(payload, secret)


@router.get("/auth/login")
async def auth_login(request: Request):
    """Begin the authorization-code flow: redirect the browser to the IdP.

    Mints ``state`` + a PKCE ``code_verifier``, stashes them (plus a sanitized
    ``return_to``) in a short-TTL signed transaction cookie, and 302s to the
    authorization endpoint with the S256 ``code_challenge``.
    """
    if not login_enabled():
        raise HTTPException(status_code=404)

    cfg = load_oidc_config()
    try:
        endpoints = resolve_endpoints(cfg)
    except OIDCError as exc:
        # Don't leak discovery internals; the operator misconfigured the IdP.
        log.warning("OIDC login: could not resolve authorization endpoint")
        raise HTTPException(status_code=500, detail="OIDC login is misconfigured") from exc

    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = _code_challenge_s256(code_verifier)
    nonce = secrets.token_urlsafe(32)
    return_to = _safe_return_to(request.query_params.get("return_to"))

    tx_payload = {
        "state": state,
        "cv": code_verifier,
        "nonce": nonce,
        "return_to": return_to,
        "jti": secrets.token_urlsafe(16),
        "exp": _now() + _TX_TTL,
    }
    fresh = bool(request.query_params.get("fresh"))
    if fresh:
        tx_payload["fresh"] = True  # the callback checks the provider really re-prompted
    tx_cookie = sign_session(tx_payload, cfg.session_secret)

    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "scope": "openid",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    # Ask the provider for the configured authentication context (a second
    # factor) when the administrator listed one; the callback still checks the
    # ID token, because a request parameter is a hint, not proof.
    try:
        from .mfa_policy import policy as _mfa_policy

        acr_values = _mfa_policy()["acr_values"]
    except Exception:
        acr_values = []
    if acr_values:
        params["acr_values"] = " ".join(acr_values)
    # ``?fresh=1`` (the step-up link): the provider must ask the person to
    # sign in again rather than reuse its own session, so ``auth_time`` and
    # the session's second factor are new.
    if fresh:
        params["prompt"] = "login"
        params["max_age"] = "0"
    auth_url = endpoints["authorization_endpoint"] + "?" + urlencode(params)

    response = RedirectResponse(auth_url, status_code=302)
    _set_cookie(
        response, TX_COOKIE, tx_cookie,
        max_age=_TX_TTL, secure=_cookie_secure(request),
    )
    return response


def _fail(return_to: str | None = None, *, reason: str = ""):
    """Build a failure response that also clears both auth cookies.

    Used on every callback error path so a half-finished/forged login leaves no
    stale transaction or session cookie behind. We surface the failure as a
    redirect to ``/auth/error`` rather than a raw 4xx so the user lands on a
    page, not a JSON blob (the CSRF/state-mismatch case is the documented
    exception — it returns a 400 inline). ``reason`` selects one of the fixed
    plain explanations that page may show (``mfa``, ``store``); anything else
    stays generic so a failure mode never leaks to an attacker.
    """
    from urllib.parse import urlencode

    params = {"return_to": _safe_return_to(return_to)}
    if reason in _ERROR_REASONS:
        params["reason"] = reason
    response = RedirectResponse("/auth/error?" + urlencode(params), status_code=303)
    _clear_cookie(response, TX_COOKIE)
    _clear_cookie(response, SESSION_COOKIE)
    return response


@router.get("/auth/callback")
async def auth_callback(request: Request):
    """Handle the IdP redirect: verify state, exchange the code, set the session.

    Order of checks (fail-closed at each step, clearing cookies on failure):
      1. tx cookie present + valid;
      2. ``state`` query param == tx-cookie state (CSRF) — else 400, NO token
         exchange;
      3. token endpoint is https; exchange the ``code`` with the PKCE verifier;
      4. verify the returned ``id_token`` via
         :func:`maverick.oidc.verify_oidc_token`;
      5. set the signed session cookie and redirect to the (sanitized)
         ``return_to``.
    """
    from .company_signin_tests import COOKIE as test_cookie
    from .company_signin_tests import finish as finish_test
    if request.cookies.get(test_cookie):
        return await finish_test(request)
    if not login_enabled():
        raise HTTPException(status_code=404)

    cfg = load_oidc_config()

    # (1) transaction cookie
    raw_tx = request.cookies.get(TX_COOKIE)
    tx = verify_session(raw_tx, cfg.session_secret) if raw_tx else None
    if not tx:
        log.warning("OIDC callback: missing/invalid transaction cookie")
        return _fail()

    # (2) CSRF: state must match. Reject BEFORE any network/token exchange.
    query_state = request.query_params.get("state") or ""
    tx_state = tx.get("state") or ""
    if not query_state or not secrets.compare_digest(query_state.encode(), tx_state.encode()):
        # CSRF: reject with 400 and clear cookies BEFORE any token exchange.
        log.warning("OIDC callback: state mismatch (possible CSRF)")
        return _csrf_reject()

    code = request.query_params.get("code") or ""
    if not code:
        log.warning("OIDC callback: no authorization code present")
        return _fail(tx.get("return_to"))

    # (3) resolve + https-check the token endpoint, then exchange the code.
    try:
        endpoints = resolve_endpoints(cfg)
    except OIDCError:
        log.warning("OIDC callback: could not resolve token endpoint")
        return _fail(tx.get("return_to"))
    token_endpoint = endpoints["token_endpoint"]
    if not token_endpoint.lower().startswith("https://"):
        log.warning("OIDC callback: refusing non-https token endpoint")
        return _fail(tx.get("return_to"))

    tx_id = str(tx.get("jti") or "")
    tx_exp = int(tx.get("exp") or 0)
    if not await _consume_tx_once(tx_id, tx_exp):
        log.warning("OIDC callback: replayed or malformed transaction cookie")
        return _fail(tx.get("return_to"))

    code_verifier = tx.get("cv") or ""
    try:
        token_data = await _exchange_code_for_tokens(
            token_endpoint, cfg=cfg, code=code, code_verifier=code_verifier
        )
    except Exception:
        # Never log the exception payload: it can echo the code/secret back.
        log.warning("OIDC callback: token exchange failed")
        await asyncio.get_running_loop().run_in_executor(
            None, _shared_release_tx, tx_id
        )
        return _fail(tx.get("return_to"))

    id_token = ""
    if isinstance(token_data, dict):
        id_token = str(token_data.get("id_token") or "")
    if not id_token:
        log.warning("OIDC callback: token response had no id_token")
        await asyncio.get_running_loop().run_in_executor(
            None, _shared_release_tx, tx_id
        )
        return _fail(tx.get("return_to"))

    # (4) verify the ID token — reuse the kernel verifier (no re-implementation).
    try:
        principal = verify_oidc_token(id_token)
    except OIDCError:
        log.warning("OIDC callback: id_token verification failed")
        await asyncio.get_running_loop().run_in_executor(
            None, _shared_release_tx, tx_id
        )
        return _fail(tx.get("return_to"))

    # (4b) bind the ID token to THIS login: its nonce must match the one we
    # sent on /auth/login (OIDC replay protection — a spec-compliant IdP echoes
    # the request nonce into the id_token).
    tx_nonce = str(tx.get("nonce") or "")
    tok_nonce = str((principal.claims or {}).get("nonce") or "")
    if tx_nonce and not secrets.compare_digest(tok_nonce.encode(), tx_nonce.encode()):
        log.warning("OIDC callback: id_token nonce mismatch (possible replay)")
        await asyncio.get_running_loop().run_in_executor(
            None, _shared_release_tx, tx_id
        )
        return _fail(tx.get("return_to"))

    # (4c) second factor: with "Require a second factor" on, the ID token must
    # prove one (RFC 8176 ``amr`` or a configured ``acr``). Refused sign-ins
    # get a page with one plain sentence, not a session.
    from .mfa_policy import claims_prove_mfa, fresh_enough, require_mfa

    mfa = claims_prove_mfa(principal.claims)
    # Date the second factor by the provider's ``auth_time``, not by this
    # callback: a provider that reuses its own SSO session (or ignores
    # prompt=login / max_age=0) returns amr=mfa for a sign-in from hours ago.
    # On a step-up (``?fresh=1``) an ID token that cannot show a recent
    # authentication is no proof of a fresh second factor.
    now = _now()
    auth_time = credible_auth_time((principal.claims or {}).get("auth_time"), now=now)
    if mfa and tx.get("fresh") and (auth_time is None or not fresh_enough(auth_time, now=now)):
        log.warning("OIDC callback: step-up sign-in without a recent auth_time; "
                    "second factor not counted")
        mfa = False
    if require_mfa() and not mfa:
        log.warning("OIDC callback: sign-in refused, no second factor in the ID token")
        await asyncio.get_running_loop().run_in_executor(
            None, _shared_release_tx, tx_id
        )
        return _fail(reason="mfa")

    # (5) success: set the signed session cookie, clear the tx cookie, redirect.
    return_to = _safe_return_to(tx.get("return_to"))
    try:
        from .session_policy import company_ttl

        ttl = company_ttl(_SESSION_TTL)
        session_cookie = mint_browser_session(
            request, sub=principal.sub, secret=cfg.session_secret, via="session",
            mfa=mfa, ttl=ttl, mfa_at=auth_time,
            extra={"oidc_issuer": principal.issuer,
                   "oidc_audience": principal.audience,
                   "idp_email": _oidc_invite_email(principal.claims or {}),
                   "verified_email": _oidc_permission_email(principal.claims or {})},
        )
    except Exception:
        log.warning("OIDC callback: session record unavailable; refusing sign-in")
        await asyncio.get_running_loop().run_in_executor(
            None, _shared_release_tx, tx_id
        )
        return _fail(reason="store")

    # Record this sub against the user's stable IdP identifiers so a later SCIM
    # deprovision can revoke this session even if the IdP's sub is pairwise and
    # appears in no SCIM attribute (Entra). Best-effort -- never blocks login.
    try:
        from .subject_directory import record_login
        claims = principal.claims or {}
        record_login(principal.sub, [
            claims.get("email"), claims.get("preferred_username"),
            claims.get("oid"), claims.get("upn"),
        ])
    except Exception:  # pragma: no cover -- directory never blocks login
        pass

    response = RedirectResponse(return_to, status_code=303)
    _set_cookie(
        response, SESSION_COOKIE, session_cookie,
        max_age=ttl, secure=_cookie_secure(request),
    )
    _clear_cookie(response, TX_COOKIE)
    return response


def _csrf_reject():
    """Return a 400 that also clears both auth cookies (state mismatch / CSRF)."""
    out = _login_error_response(status_code=400)
    _clear_cookie(out, TX_COOKIE)
    _clear_cookie(out, SESSION_COOKIE)
    return out


def _logout_origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        if (scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            return None
        port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
        return scheme, parsed.hostname.lower().rstrip("."), port
    except ValueError:
        return None


def _is_same_origin_logout(request: Request) -> bool:
    """Compare full public origins; never trust unverified forwarding headers."""
    public = os.environ.get("MAVERICK_PUBLIC_URL", "").strip()
    if not public:
        try:
            from maverick.config import load_config

            public = str((load_config().get("dashboard") or {}).get("public_url") or "").strip()
        except Exception:
            return False
    if not public and login_enabled():
        try:
            public = str(getattr(load_oidc_config(), "redirect_uri", "") or "").strip()
        except Exception:
            return False
    expected = _logout_origin(public or str(request.base_url))
    if expected is None:
        return False
    for header in ("origin", "referer"):
        value = request.headers.get(header)
        if value:
            return _logout_origin(value) == expected
    return False


def _post_logout_redirect(cfg) -> str:
    """Absolute URL the IdP returns the browser to after logout: the app origin.

    Derived from the configured ``redirect_uri`` so it matches the deployment's
    public host. It must be registered in the IdP's post-logout allow-list
    (Auth0: *Allowed Logout URLs*); an unlisted URL makes the IdP reject the
    logout, so we only send one we can derive deterministically.
    """
    ru = (getattr(cfg, "redirect_uri", "") or "").strip()
    if not ru:
        return ""
    parsed = urlparse(ru)
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}/"


def _configured_end_session_endpoint() -> str:
    """The IdP ``end_session_endpoint`` (RP-initiated logout), from configuration.

    Resolved from ``MAVERICK_OIDC_END_SESSION_ENDPOINT`` (env) or the
    ``[auth.oidc].end_session_endpoint`` config key. Deliberately read here in the
    dashboard package rather than added to :mod:`maverick.oidc`'s discovery: the
    benchmark control-source snapshot hashes ``packages/maverick-core/maverick``,
    so an OIDC field there would invalidate the signed harness-overhead /
    governance-frontier manifests. ``https``-only; ``""`` when unset or not https.
    """
    value = (os.environ.get("MAVERICK_OIDC_END_SESSION_ENDPOINT") or "").strip()
    if not value:
        try:
            from maverick.config import load_config

            section = ((load_config() or {}).get("auth") or {}).get("oidc") or {}
            value = str(section.get("end_session_endpoint", "") or "").strip()
        except Exception:  # pragma: no cover - missing/unreadable config is not a session
            value = ""
    return value if value.lower().startswith("https://") else ""


def _idp_logout_url(cfg) -> str | None:
    """RP-initiated logout URL at the IdP, or ``None`` for local-only logout.

    Clearing the local ``mvk_session`` cookie ends the *app* session but not the
    IdP's own SSO session, so the next ``/auth/login`` silently re-authenticates
    and the user is never actually logged out. When an ``end_session_endpoint`` is
    configured (OIDC RP-initiated logout; Auth0's ``/oidc/logout``), send the
    browser there after clearing the cookie so the IdP session ends too. Returns
    ``None`` (prior local-only behaviour) when none is configured, so deployments
    without one are unaffected.
    """
    end_session = _configured_end_session_endpoint()
    if not end_session:
        return None
    params: dict[str, str] = {}
    if getattr(cfg, "client_id", ""):
        params["client_id"] = cfg.client_id
    post_logout = _post_logout_redirect(cfg)
    if post_logout:
        params["post_logout_redirect_uri"] = post_logout
    return end_session + ("?" + urlencode(params) if params else "")


def browser_session_enabled() -> bool:
    """Whether this installation supports a browser session that can end."""
    if login_enabled():
        return True
    from .invites import local_login_mode
    from .saml import saml_enabled

    return saml_enabled() or local_login_mode()


@router.get("/auth/logout")
def auth_logout(request: Request):
    """Show a confirmation without changing any session."""
    if not browser_session_enabled():
        raise HTTPException(status_code=404)
    from .app import templates

    return templates.TemplateResponse(
        request, "auth_logout.html", {"all_sessions": bool(request.query_params.get("all"))},
        headers={"Cache-Control": "private, no-store"},
    )


@router.post("/auth/logout")
def auth_logout_confirmed(request: Request):
    """End this session, or revoke all sessions on a same-origin request."""
    if not browser_session_enabled():
        raise HTTPException(status_code=404)
    if not _is_same_origin_logout(request):
        raise HTTPException(status_code=403, detail="Sign out from the Lightwork page.")
    if request.query_params.get("all"):
        # Derive the sub from the verified session payload DIRECTLY, not via
        # _principal_from_request_session -- that returns None for an
        # already-revoked session, so "log out everywhere" on a session that was
        # revoked once would silently skip and leave OTHER (newer) bearers alive.
        # Re-bumping the epoch to now catches any credential minted since.
        sub = _session_sub_unchecked(request)
        if sub:
            from .session_revocation import revoke_principal
            revoke_principal(sub)
    # End the IdP's SSO session too (RP-initiated logout), not just the local
    # cookie -- otherwise the next /auth/login silently re-authenticates and the
    # user never actually logs out. Falls back to "/" when the IdP advertises no
    # end_session_endpoint. The local cookie is cleared either way.
    # Local-owner, invite and SAML cookies also need a working local sign-out.
    # Only an enabled OIDC login can supply an OIDC end-session redirect. This
    # does not claim to end the upstream SAML identity-provider session.
    _end_this_session(request)
    destination = _idp_logout_url(load_oidc_config()) if login_enabled() else None
    response = RedirectResponse(destination or "/", status_code=303)
    _clear_cookie(response, SESSION_COOKIE)
    return response


def _end_this_session(request: Request) -> None:
    """Mark this session ended in the registry, so a copied cookie stops working
    and the Sessions page no longer lists it as live. Never blocks sign-out."""
    payload = _session_payload_unchecked(request) or {}
    sid = payload.get("sid")
    if not isinstance(sid, str) or not sid:
        return
    from . import session_registry

    try:
        session_registry.revoke(sid, by=f"user:{payload.get('sub')}")
    except session_registry.SessionStoreError:
        log.warning("sign-out could not mark the session record ended")


def _session_sub_unchecked(request: Request) -> str | None:
    """The ``sub`` from a validly-signed, unexpired session cookie, WITHOUT the
    revocation check -- so "log out everywhere" can revoke even when the session
    is already revoked. Returns None when the cookie is absent/tampered/expired."""
    from maverick.oidc import validate_subject

    payload = _session_payload_unchecked(request)
    if not payload:
        return None
    try:
        return validate_subject(payload.get("sub"))
    except ValueError:
        return None


def _session_payload_unchecked(request: Request) -> dict | None:
    """The payload of a validly-signed, unexpired session cookie, without the
    revocation check. None when the cookie is absent, tampered or expired."""
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    from .invites import local_login_mode, local_session_secret
    from .saml import saml_enabled

    secrets = []
    oidc = login_enabled()
    if oidc or saml_enabled():
        secrets.append(load_oidc_config().session_secret)
    if not oidc and local_login_mode():
        secrets.append(local_session_secret())
    for secret in secrets:
        payload = verify_session(raw, secret) if secret else None
        if payload:
            return payload
    return None


_ERROR_REASONS = {
    "mfa": ("Sign in again with your authenticator", None),
    "store": ("Sign-in could not be recorded",
              "Lightwork could not record this sign-in, so it was not completed. "
              "Try again; if it keeps happening, ask an administrator to check the server."),
}


@router.get("/auth/error")
async def auth_error(request: Request):
    """Login-failure landing page.

    Generic by default (no detail that aids an attacker). The two documented
    reasons are the person's own to act on: a sign-in without a second factor
    while one is required, and a session record that could not be written."""
    if not login_enabled():
        raise HTTPException(status_code=404)
    reason = request.query_params.get("reason", "")
    if reason in _ERROR_REASONS:
        from .app import templates
        from .mfa_policy import MFA_MISSING_MESSAGE

        title, message = _ERROR_REASONS[reason]
        # The person has no session yet: the public shell, not the app's.
        return templates.TemplateResponse(
            request, "auth_error.html",
            {"title": title, "message": message or MFA_MISSING_MESSAGE,
             "action_href": "/auth/login?fresh=1", "action_label": "Sign in again"},
            status_code=403, headers={"Cache-Control": "no-store"},
        )
    return _login_error_response(request.query_params.get("return_to"))


def _login_error_response(return_to: str | None = None, *, status_code: int = 401):
    from urllib.parse import urlencode

    from .app import templates

    template = templates.env.get_template("auth_error.html")
    return HTMLResponse(template.render(
        restart_url="/auth/login?" + urlencode({"return_to": _safe_return_to(return_to)}),
    ), status_code=status_code, headers={"Cache-Control": "no-store"})


__all__ = [
    "router",
    "TX_COOKIE",
    "SESSION_COOKIE",
    "mint_browser_session",
    "session_claims",
    "_principal_from_request_session",
    "_consume_tx_once",
    "_exchange_code_for_tokens",
]
