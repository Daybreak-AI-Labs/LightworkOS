"""When the browser's sign-in ends, and staying signed in (WCAG 2.2.1).

Pages carry the signed session's end time so ``lightwork-session.js`` can warn
before it ends and offer to stay signed in. A local (passphrase) sign-in is
kept going here: the session is replaced by a new one of the usual length and
the old one is ended, so the Sessions page still lists exactly one. A company
(OIDC or SAML) sign-in keeps its original ceiling and current shorter
installation limit. Activity can extend only the inactivity deadline. "Stay
signed in" returns to the company provider when the absolute sign-in is ending.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

router = APIRouter()
_HEADERS = {"Cache-Control": "no-store"}


def _payload(request: Request) -> tuple[dict, str] | None:
    """The verified session cookie and how it was signed ("local" or "company")."""
    from maverick.web_session import verify_session

    from .oidc_login import SESSION_COOKIE

    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    try:
        from . import invites

        if invites.local_login_mode():
            payload = verify_session(raw, invites.local_session_secret())
            return (payload, "local") if isinstance(payload, dict) else None
        from maverick.oidc import load_oidc_config

        secret = load_oidc_config().session_secret
        payload = verify_session(raw, secret) if secret else None
        return (payload, "company") if isinstance(payload, dict) else None
    except Exception:  # an unreadable sign-in configuration shows no timer
        return None


def _ends(payload: dict, *, company: bool = False) -> int | None:
    from . import session_registry
    from .session_policy import company_ttl, idle_minutes
    from .session_revocation import is_revoked

    value = payload.get("exp")
    if not isinstance(value, (int, float)) or is_revoked(payload.get("sub", ""), payload.get("iat")):
        return None
    try:
        sid = payload.get("sid")
        if sid:
            row = session_registry.current(sid, principal=f"user:{payload.get('sub')}")
            if row is None:
                return None
            value = min(value, row.effective_end)
        elif idle_minutes():
            return None
        elif company:
            value = min(value, float(payload["iat"]) + company_ttl(12 * 3600))
        return int(value) if value > time.time() else None
    except (KeyError, TypeError, ValueError, OSError):
        return None
    except session_registry.SessionStoreError:
        return None


def sign_in_path() -> str:
    """Where this installation signs people in (``return_to`` is added by the page)."""
    try:
        from maverick.oidc import login_enabled

        if login_enabled():
            return "/auth/login"
        from .saml import saml_enabled

        if saml_enabled():
            return "/saml/login"
    except Exception:
        pass
    return "/auth/local-login"


def page_session(request: Request) -> dict | None:
    """For the page shell: the session's end, the server clock and how to keep it."""
    found = _payload(request)
    ends = _ends(found[0], company=found[1] == "company") if found else None
    if ends is None:
        return None
    from .session_policy import idle_minutes

    return {"expires_at": ends, "now": int(time.time()), "idle_minutes": idle_minutes(),
            "renew": "renew" if found[1] == "local" else "sign-in", "sign_in": sign_in_path()}


@router.get("/auth/session/status")
def session_status(request: Request) -> JSONResponse:
    """The current end time (another tab may have kept the session going)."""
    found = page_session(request)
    if found is None:
        return JSONResponse({"signed_in": False}, headers=_HEADERS)
    from .session_policy import idle_minutes

    return JSONResponse({"signed_in": True, "expires_at": found["expires_at"], "now": found["now"],
                         "renew": found["renew"], "idle_minutes": idle_minutes()}, headers=_HEADERS)


@router.post("/auth/session/activity")
def record_activity(request: Request) -> JSONResponse:
    """Keep this active signed browser session current; never renew an ended one."""
    from . import session_registry
    from .app import _require_same_origin

    _require_same_origin(request)
    found = _payload(request)
    if found is None or _ends(found[0], company=found[1] == "company") is None or not found[0].get("sid"):
        raise HTTPException(401, "Your sign-in has ended. Sign in again to continue.")
    client = getattr(request, "client", None)
    session_registry.touch(found[0]["sid"], activity=True,
                           ip=str(getattr(client, "host", "") or ""),
                           user_agent=request.headers.get("user-agent", ""))
    ends = _ends(found[0], company=found[1] == "company")
    if ends is None:
        raise HTTPException(401, "Your sign-in has ended. Sign in again to continue.")
    return JSONResponse({"expires_at": ends, "now": int(time.time())}, headers=_HEADERS)


@router.post("/auth/session/renew")
def renew_session(request: Request) -> JSONResponse:
    """Replace a live local sign-in with a new one; end the old one."""
    from .app import _require_same_origin
    from .invites import local_session_principal, mint_local_session, session_ttl_seconds
    from .oidc_login import SESSION_COOKIE, _cookie_secure, _set_cookie

    _require_same_origin(request)
    found = _payload(request)
    if found is None or _ends(found[0], company=found[1] == "company") is None:
        raise HTTPException(401, "Your sign-in has ended. Sign in again to continue.")
    if found[1] != "local":
        return JSONResponse({"renew": "sign-in", "sign_in": sign_in_path()}, status_code=409, headers=_HEADERS)
    principal = local_session_principal(request)
    if principal is None:
        raise HTTPException(401, "Your sign-in has ended. Sign in again to continue.")
    # The replacement keeps the second factor, and when it was given, if this sign-in had one.
    from .mfa_policy import principal_mfa
    proved, proved_at = principal_mfa(principal)
    token = mint_local_session(principal.sub, request=request, mfa=proved,
                               mfa_at=proved_at if proved else None)
    from maverick.web_session import verify_session

    from .invites import local_session_secret

    ttl = session_ttl_seconds()
    minted = verify_session(token, local_session_secret()) or {}
    effective = _ends(minted)
    if effective is None:
        # The replacement is not usable, so the sign-in the person still has
        # must stay: ending it first would sign them out for nothing.
        raise HTTPException(401, "Your sign-in has ended. Sign in again to continue.")
    old_sid = (principal.claims or {}).get("sid") or ""
    if old_sid:
        from . import session_registry

        session_registry.revoke(old_sid, by="renewed")
    response = JSONResponse({"expires_at": effective}, headers=_HEADERS)
    _set_cookie(response, SESSION_COOKIE, token, max_age=ttl, secure=_cookie_secure(request))
    return response
