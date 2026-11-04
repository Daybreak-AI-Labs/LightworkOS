"""Sessions: who is signed in, from where, and the buttons that end it.

Page ``/settings/sessions`` lists the caller's own browser sessions (from
:mod:`session_registry`) and, for an installation-wide administrator, every
person's. API under ``/api/v1/sessions`` returns the same rows as JSON.

Ending a session:

* "Sign out this device" ends one session by its id;
* "Sign out everywhere" ends every recorded session of one person and also
  bumps their revocation epoch (:mod:`session_revocation`), so untracked
  legacy cookies and API bearers issued before now stop working too.

A person may end only their own sessions; an administrator may end anyone's.
Every revoke is a sensitive action (:mod:`step_up`) and writes one
control-plane audit row. Ending a sign-in takes effect first: the activity log
refusing the row cannot keep someone signed in, so it is reported (503) after
the fact instead. A bearer API key may not end sessions at all.
"""
from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from . import auth, session_registry, step_up

router = APIRouter(tags=["sessions"])

PAGE = "/settings/sessions"
API = "/api/v1/sessions"


def _app():
    from . import app as app_module

    return app_module


def _caller(request: Request) -> tuple[str | None, bool, str]:
    """``(principal, is_admin, current_sid)`` for this request."""
    principal = auth.caller_principal(request)
    is_admin = auth.has_global_permission(request, "admin")
    state_principal = getattr(getattr(request, "state", None), "principal", None)
    claims = getattr(state_principal, "claims", None) or {}
    return principal, bool(is_admin), str(claims.get("sid") or "")


def _audit_revoke(request: Request, *, target: str, sid: str, count: int, everywhere: bool) -> None:
    from maverick.audit import AuditRefused, EventKind, audit_event

    try:
        audit_event(
            EventKind.CONTROL_PLANE_ACTION, agent="dashboard", _global=True,
            verb="revoke_sessions", principal=target,
            actor=auth.caller_principal(request) or "local administrator",
            ok=True, session=sid, count=count,
            detail="signed out everywhere" if everywhere else "signed out one device",
        )
    except AuditRefused as exc:
        # Ending a sign-in is never held back by the log, so by now it has taken
        # effect; say so rather than reporting a failure that did not happen.
        raise HTTPException(
            status_code=503,
            detail="The sessions were signed out, but the activity log refused to record it. "
                   "Tell an administrator.") from exc


def _rows_for(request: Request, principal_filter: str | None, *, everyone: bool) -> list[dict]:
    principal, is_admin, current = _caller(request)
    if principal_filter and principal_filter != principal and not is_admin:
        raise HTTPException(status_code=403,
                            detail="Only an administrator can see other people's sessions.")
    try:
        if principal_filter:
            rows = session_registry.list_for(principal_filter)
        elif everyone and (is_admin or principal is None):
            rows = session_registry.list_all()
        elif principal is None:
            rows = []
        else:
            rows = session_registry.list_for(principal)
    except session_registry.SessionStoreError as exc:
        raise HTTPException(status_code=503,
                            detail="The session record cannot be read right now.") from exc
    from .session_revocation import is_revoked

    out = []
    for row in rows:
        # A SCIM deprovision or "log out everywhere" bumps the epoch without
        # touching these rows: hide what the epoch already ended.
        if is_revoked(row.principal.removeprefix("user:"), row.issued_at):
            continue
        item = row.as_dict()
        item["current"] = bool(current) and row.sid == current
        item["method"] = _method_label(row.via)
        item["issued_text"] = _when(row.issued_at)
        item["last_seen_text"] = _when(row.last_seen)
        out.append(item)
    return out


def _when(ts: float | None) -> str:
    import datetime as _dt

    if ts is None:
        return "—"
    try:
        return _dt.datetime.fromtimestamp(float(ts), tz=_dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return "—"


def _method_label(via: str) -> str:
    return {"session": "Company sign-in", "invite": "Email and passphrase",
            "proxy": "Company proxy"}.get(via, via or "Unknown")


def _require_signed_in_person(request: Request) -> None:
    """Ending sign-ins is for a signed-in person. A bearer key (even one that
    can only read) must not end its owner's sessions, which would also end
    every key the owner made."""
    if auth.api_key_permissions(request) is not None:
        raise HTTPException(
            status_code=403,
            detail="An API key cannot end sign-in sessions. Sign in and use Account > Sessions.")


def _revoke_one(request: Request, sid: str) -> dict:
    _require_signed_in_person(request)
    principal, is_admin, current = _caller(request)
    step_up.require_recent_mfa(request, "revoke_sessions")
    try:
        record = session_registry.get(sid)
    except session_registry.SessionStoreError as exc:
        raise HTTPException(status_code=503,
                            detail="The session record cannot be read right now.") from exc
    if record is None:
        raise HTTPException(status_code=404, detail="That session was not found.")
    if record.principal != principal and not is_admin:
        raise HTTPException(status_code=403,
                            detail="Only an administrator can sign other people out.")
    actor = principal or "local administrator"
    try:
        session_registry.revoke(sid, by=actor)
    except session_registry.SessionStoreError as exc:
        raise HTTPException(status_code=503,
                            detail="The session record cannot be read right now.") from exc
    _audit_revoke(request, target=record.principal, sid=sid, count=1, everywhere=False)
    return {"revoked": 1, "principal": record.principal, "current": sid == current}


def _revoke_everywhere(request: Request, target: str | None) -> dict:
    _require_signed_in_person(request)
    principal, is_admin, current = _caller(request)
    step_up.require_recent_mfa(request, "revoke_sessions")
    target = (target or "").strip() or principal
    if not target:
        raise HTTPException(status_code=400, detail="Choose whose sessions to end.")
    if target != principal and not is_admin:
        raise HTTPException(status_code=403,
                            detail="Only an administrator can sign other people out.")
    actor = principal or "local administrator"
    try:
        count = session_registry.revoke_all(target, by=actor)
    except session_registry.SessionStoreError as exc:
        raise HTTPException(status_code=503,
                            detail="The session record cannot be read right now.") from exc
    from .session_revocation import revoke_principal

    # The epoch also ends legacy cookies and API bearers issued before now.
    revoke_principal(target.removeprefix("user:"))
    _audit_revoke(request, target=target, sid="", count=count, everywhere=True)
    return {"revoked": count, "principal": target, "current": target == principal}


# ---------------------------------------------------------------- the page


@router.get(PAGE, response_class=HTMLResponse)
def sessions_page(request: Request, principal: str = "", saved: str = "") -> HTMLResponse:
    """My sessions; an administrator also sees everyone's."""
    me, is_admin, _current = _caller(request)
    everyone = is_admin or me is None
    rows = _rows_for(request, principal or None, everyone=everyone and not principal)
    from .mfa_policy import require_mfa

    saved_text = {"one": "That device was signed out.",
                  "all": "Every session for that person was signed out."}.get(saved, "")
    return _app().templates.TemplateResponse(request, "sessions.html", {
        "rows": rows, "you": me, "is_admin": is_admin, "filter_principal": principal,
        "everyone": everyone and not principal, "saved": saved_text,
        "mfa_required": require_mfa(),
        "people": sorted({r["principal"] for r in rows}),
    })


@router.post(PAGE + "/revoke")
def sessions_revoke_form(request: Request, sid: str = Form(...)) -> RedirectResponse:
    _app()._require_same_origin(request)
    result = _revoke_one(request, sid.strip())
    if result["current"]:
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie("mvk_session", path="/")
        return response
    return RedirectResponse(PAGE + "?saved=one", status_code=303)


@router.post(PAGE + "/revoke-all")
def sessions_revoke_all_form(request: Request, principal: str = Form("")) -> RedirectResponse:
    _app()._require_same_origin(request)
    result = _revoke_everywhere(request, principal)
    if result["current"]:
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie("mvk_session", path="/")
        return response
    return RedirectResponse(PAGE + "?saved=all", status_code=303)


# ----------------------------------------------------------------- the API


class RevokeAllIn(BaseModel):
    principal: str | None = None


@router.get(API)
async def sessions_list(request: Request, principal: str = "", all: bool = False) -> dict:  # noqa: A002
    rows = await run_in_threadpool(_rows_for, request, principal or None, everyone=all)
    return {"sessions": rows}


@router.delete(API + "/{sid}")
async def sessions_revoke(request: Request, sid: str) -> JSONResponse:
    _app()._require_same_origin(request)
    result = await run_in_threadpool(_revoke_one, request, sid)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@router.post(API + "/revoke-all")
async def sessions_revoke_all(request: Request, body: RevokeAllIn | None = None) -> JSONResponse:
    _app()._require_same_origin(request)
    target = body.principal if body is not None else None
    result = await run_in_threadpool(_revoke_everywhere, request, target)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


__all__ = ["router", "PAGE", "API"]
