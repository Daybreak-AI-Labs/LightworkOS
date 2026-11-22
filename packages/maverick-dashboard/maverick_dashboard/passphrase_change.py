"""Change your own passphrase while signed in.

For people who sign in with a passphrase: the installation owner on this
computer (:mod:`local_owner`) and invited colleagues (:mod:`local_passphrases`).
The current passphrase is checked with the same rules, hashing and lockout as
sign-in, plus the owner's authenticator code when the owner has one. Before the
new passphrase is saved, an activity-log row is written and every browser
session for the person is ended; if either fails, nothing changes. This
browser then gets a new session. Access keys and paired phones are not ended
here; the Sessions page's "Sign out everywhere" ends those too.

People who sign in with a company account change their password there.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from . import auth, local_owner, local_passphrases

router = APIRouter()

PAGE = "/account/passphrase"
_FIELDS = {"current", "password", "password2", "code"}


def _who(request: Request) -> tuple[str, str] | None:
    """``("owner" | "colleague", email)`` for a person who signs in with a passphrase here."""
    principal = auth.caller_principal(request) or ""
    if not principal.startswith("user:"):
        return None
    email = principal[len("user:"):]
    try:
        row = local_owner._read()
    except HTTPException:
        row = None
    if row is not None and row["status"] == "ready" and row["email"] == email:
        return "owner", email
    try:
        if local_passphrases.available() and local_passphrases.has_account(email):
            return "colleague", email
    except HTTPException:
        return None
    return None


def offered(request: Request) -> bool:
    """Whether the account page links here."""
    return _who(request) is not None


def _needs_code() -> bool:
    try:
        row = local_owner._read()
    except HTTPException:
        return False
    return row is not None and "totp" in row


def _page(request: Request, *, message: str = "", status_code: int = 200) -> HTMLResponse:
    from .app import templates

    who = _who(request)
    response = templates.TemplateResponse(request, "account_passphrase.html", {
        "page": PAGE, "who": who[0] if who else "", "message": message,
        "needs_code": who is not None and who[0] == "owner" and _needs_code(),
        "changed": request.query_params.get("changed") == "1" and not message,
    }, status_code=status_code)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def _change(request: Request, kind: str, email: str, current: str, new: str, code: str) -> str:
    """Save the new passphrase and return this browser's new session token."""
    from . import invites, session_registry
    from .audit_actions_api import _audit_event

    prepared = local_passphrases.prepare(email, new)  # the rules (422) and the slow hash
    principal = "user:" + email

    def before_commit(_row: dict) -> None:
        # The record and the sign-outs come first: a refusal leaves the old
        # passphrase and every session as they were.
        _audit_event(request, "passphrase_changed", principal=principal, account=kind,
                     other_sessions="ended")
        try:
            session_registry.revoke_all(principal, by=principal)
        except session_registry.SessionStoreError as exc:
            raise HTTPException(503, "Your sessions could not be checked right now. "
                                     "Nothing was changed; try again in a moment.") from exc

    if kind == "owner":
        row = local_owner.change_passphrase(request, current=current, prepared=prepared, code=code,
                                            before_commit=before_commit)
        return local_owner._finish(row, request, mfa_at=time.time() if "totp" in row else None)
    local_passphrases.change(email, current, prepared, before_commit=before_commit)
    return invites.mint_local_session(email, request=request)


@router.get(PAGE, response_class=HTMLResponse)
def change_page(request: Request) -> HTMLResponse:
    auth.require_permission(request, "view")
    return _page(request)


@router.post(PAGE, response_class=HTMLResponse)
async def change_submit(request: Request):
    from .local_owner_mfa_routes import _fields

    try:
        auth.require_permission(request, "view")
        # Per client address, before anything is read or hashed (as for sign-in).
        local_passphrases.limit_attempts(request)
        who = _who(request)
        if who is None:
            raise HTTPException(404, "Your sign-in does not use a passphrase here. If you sign in with a "
                                     "company account, change your password with your company.")
        kind, email = who
        if kind == "owner":
            local_owner._local(request, mutate=True)
        else:
            local_passphrases.require_same_origin(request)
        fields = await _fields(request, _FIELDS)
        current, new = fields.get("current", ""), fields.get("password", "")
        if new != fields.get("password2", ""):
            raise HTTPException(422, "The new passphrases do not match. Type the same new passphrase in both boxes.")
        if new == current:
            raise HTTPException(422, "Choose a new passphrase that is different from your current one.")
        token = await run_in_threadpool(_change, request, kind, email, current, new, fields.get("code", ""))
    except HTTPException as exc:
        response = _page(request, message=str(exc.detail), status_code=exc.status_code)
        if exc.status_code == 429:
            response.headers["Retry-After"] = "60"
        return response
    from .invites import session_ttl_seconds
    from .oidc_login import _cookie_secure, _set_cookie

    response = RedirectResponse(PAGE + "?changed=1", status_code=303)
    _set_cookie(response, "mvk_session", token, max_age=session_ttl_seconds(), secure=_cookie_secure(request))
    response.headers["Cache-Control"] = "no-store"
    return response


__all__ = ["PAGE", "offered", "router"]
