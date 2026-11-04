"""Pages and forms for the owner's authenticator app (see local_owner_second_factor).

``POST /auth/owner-second-factor`` finishes a sign-in that needed a code. The
``/account/owner-authenticator`` page turns the app on or off and makes new
recovery codes; it is for the owner, signed in on this computer.
"""
from __future__ import annotations

from urllib.parse import parse_qs, urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from . import auth, local_owner, local_passphrases
from . import local_owner_second_factor as second

router = APIRouter()

PAGE = "/account/owner-authenticator"
SECOND_STEP = "/auth/owner-second-factor"


def _templates():
    from .app import templates

    return templates


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def _step_page(request, *, view: str, action: str, cancel: str, status_code: int = 200,
               message: str = "", secret: str = "", uri: str = "", codes=(), next_href: str = "/start"):
    return _no_store(_templates().TemplateResponse(request, "owner_second_factor.html", {
        "view": view, "action": action, "cancel": cancel, "message": message,
        "secret": secret, "uri": uri, "codes": list(codes), "next_href": next_href,
    }, status_code=status_code))


def safe_return_to(value: object) -> str:
    """A page the owner may return to after the second step: a local path, never a sign-in page."""
    from .oidc_login import _is_safe_return_to

    if isinstance(value, str) and _is_safe_return_to(value) and not value.startswith("/auth/"):
        return value
    return ""


def challenge_response(request: Request, challenge: second.Challenge, *, status_code: int = 200,
                       message: str = "", return_to: str = "") -> HTMLResponse:
    """The page that asks for the code. The second-step token goes in a short-lived cookie.

    ``return_to`` (already checked by :func:`safe_return_to`) rides on the form's
    address, so the second step can send the owner back to the same page.
    """
    from .oidc_login import _cookie_secure

    action = SECOND_STEP + ("?" + urlencode({"return_to": return_to}) if return_to else "")
    if challenge.purpose == "enroll":
        response = _step_page(request, view="setup", action=action, cancel="/auth/local-login",
                              status_code=status_code, message=message, secret=challenge.secret,
                              uri=challenge.uri)
    else:
        response = _step_page(request, view="code", action=action, cancel="/auth/local-login",
                              status_code=status_code, message=message)
    response.set_cookie(second.COOKIE, challenge.token, max_age=second.PENDING_SECONDS,
                        path=second.COOKIE_PATH, httponly=True, samesite="strict",
                        secure=_cookie_secure(request))
    return response


def _set_session(request: Request, response, session: str) -> None:
    from .invites import session_ttl_seconds
    from .oidc_login import _cookie_secure, _set_cookie

    _set_cookie(response, "mvk_session", session, max_age=session_ttl_seconds(),
                secure=_cookie_secure(request))
    response.delete_cookie(second.COOKIE, path=second.COOKIE_PATH)
    response.headers["Cache-Control"] = "no-store"


def passphrase_step(request: Request, produce, *, headers: dict, completes: str = ""):
    """The JSON answer for a restricted step that checks the owner's passphrase and code.

    A proof that this step issued reaches the browser even when the step is then
    refused, so an accepted code is never spent for nothing. The refusal itself is
    raised, so the app's error handler answers it as on every other route; the
    proof's cookie and the no-store header travel in the refusal's headers.
    ``completes`` names the flow whose last step this is: its proof is spent once
    the step succeeds.
    """
    try:
        response = JSONResponse(produce(), headers=headers)
    except HTTPException as exc:
        exc.headers = {**headers, **(exc.headers or {}), **second.proof_headers(request)}
        raise
    if completes:
        second.close_flow(response, flow=completes)
    else:
        second.attach_proof(request, response)
    return response


def cancel_flow(request: Request, flow: str) -> JSONResponse:
    """Cancel a restricted flow: spends the recovery proof this browser holds for it.

    No passphrase is needed, because a cancel only ends authority. A request that
    does not present the flow's proof changes nothing.
    """
    local_owner._local(request, mutate=True)
    response = JSONResponse({"cancelled": True}, headers={"Cache-Control": "private, no-store"})
    second.close_flow(response, flow=flow, presented=request.cookies.get(second.PROOF_COOKIE) or "")
    return response


def _retry_after(response, exc: HTTPException) -> None:
    if exc.status_code == 429:
        response.headers["Retry-After"] = "60"


async def _fields(request: Request, allowed: set[str]) -> dict[str, str]:
    """One value for each named form field, from a bounded urlencoded body."""
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/x-www-form-urlencoded":
        raise HTTPException(415, "Submit the form from this page.")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 16384:
            raise HTTPException(413, "The form exceeds its supported size.")
    try:
        data = parse_qs(bytes(body).decode("utf-8"), max_num_fields=5, keep_blank_values=True)
    except (UnicodeError, ValueError) as exc:
        raise HTTPException(422, "Check the submitted form values.") from exc
    if set(data) - allowed or any(len(v) != 1 for v in data.values()):
        raise HTTPException(422, "Submit one value for each field.")
    return {k: v[0] for k, v in data.items()}


@router.post(SECOND_STEP, response_class=HTMLResponse)
async def second_step_submit(request: Request):
    from .local_owner_routes import _form

    token = request.cookies.get(second.COOKIE) or ""
    return_to = safe_return_to(request.query_params.get("return_to"))
    try:
        local_owner._local(request, mutate=True)
        # Per client address, as for the passphrase step.
        local_passphrases.limit_attempts(request)
        fields = await _fields(request, {"code"})
        finished = await run_in_threadpool(second.complete, request, token=token,
                                           code=fields.get("code", ""))
    except HTTPException as exc:
        challenge = second.challenge_for(token) if exc.status_code == 401 else None
        if challenge is not None:
            response = challenge_response(request, challenge, status_code=exc.status_code,
                                          message=str(exc.detail), return_to=return_to)
        else:
            response = _form(request, setup=False, message=str(exc.detail), status=exc.status_code)
            response.delete_cookie(second.COOKIE, path=second.COOKIE_PATH)
        _retry_after(response, exc)
        return response
    except Exception:
        return _form(request, setup=False, message="Sign-in could not finish. Try again in a moment.", status=503)
    if finished.recovery_codes:
        response = _step_page(request, view="codes", action="", cancel="", next_href="/start",
                              codes=finished.recovery_codes,
                              message="Your authenticator app is on. Save these recovery codes now. "
                                      "Each works once, and they are not shown again.")
    else:
        response = RedirectResponse(return_to or "/start", status_code=303)
    _set_session(request, response, finished.session)
    return response


def owner_link_visible(request: Request) -> bool:
    """Whether the account page offers the authenticator app: only to the owner signed in here.

    Hidden when the option is off and no app is on, since the page could only say so.
    """
    try:
        row = local_owner._read()
        if row is None or row["status"] != "ready":
            return False
        if auth.caller_principal(request) != "user:" + row["email"]:
            return False
        return second.mode() != "off" or "totp" in row
    except HTTPException:
        return False


def _owner_row(request: Request, *, mutate: bool = False) -> dict:
    """The owner record, for the owner signed in on this computer."""
    local_owner._local(request, mutate=mutate)
    local_owner._policy()
    row = local_owner._read()
    if row is None or row["status"] != "ready":
        raise HTTPException(409, "Complete this computer's owner setup before using the authenticator app.")
    if auth.caller_principal(request) != "user:" + row["email"]:
        raise HTTPException(403, "Sign in as the owner of this installation to manage its authenticator app.")
    return row


def _manage_page(request: Request, row: dict, *, message: str = "", status_code: int = 200):
    return _no_store(_templates().TemplateResponse(request, "owner_authenticator.html", {
        "state": second.status(row), "message": message, "page": PAGE,
    }, status_code=status_code))


@router.get(PAGE, response_class=HTMLResponse)
def authenticator_page(request: Request):
    return _manage_page(request, _owner_row(request))


@router.post(PAGE + "/setup", response_class=HTMLResponse)
async def setup_submit(request: Request):
    try:
        _owner_row(request, mutate=True)
        fields = await _fields(request, {"password"})
        secret, uri = await run_in_threadpool(second.start_setup, fields.get("password", ""))
    except HTTPException as exc:
        return _manage_page(request, local_owner._read() or {}, message=str(exc.detail),
                            status_code=exc.status_code)
    return _step_page(request, view="setup", action=PAGE + "/confirm", cancel=PAGE,
                      secret=secret, uri=uri, message="Add this account to your authenticator app, then "
                      "type the six-digit code it shows.")


@router.post(PAGE + "/confirm", response_class=HTMLResponse)
async def setup_confirm(request: Request):
    try:
        _owner_row(request, mutate=True)
        fields = await _fields(request, {"code"})
        codes = await run_in_threadpool(second.confirm_setup, fields.get("code", ""))
    except HTTPException as exc:
        if exc.status_code == 401:
            pending = second.pending_setup()
            if pending is not None:
                text, uri = pending
                return _step_page(request, view="setup", action=PAGE + "/confirm", cancel=PAGE,
                                  status_code=401, secret=text, uri=uri, message=str(exc.detail))
        row = local_owner._read() or {}
        return _manage_page(request, row, message=str(exc.detail), status_code=exc.status_code)
    return _step_page(request, view="codes", action="", cancel="", next_href=PAGE, codes=codes,
                      message="Your authenticator app is on. Save these recovery codes now. Each works "
                              "once, and they are not shown again.")


@router.post(PAGE + "/disable", response_class=HTMLResponse)
async def disable_submit(request: Request):
    try:
        _owner_row(request, mutate=True)
        fields = await _fields(request, {"password", "code"})
        await run_in_threadpool(second.disable, password=fields.get("password", ""),
                                code=fields.get("code", ""))
    except HTTPException as exc:
        return _manage_page(request, local_owner._read() or {}, message=str(exc.detail),
                            status_code=exc.status_code)
    return _manage_page(request, local_owner._read() or {},
                        message="Your authenticator app is off. Sign-in uses your passphrase only.")


@router.post(PAGE + "/recovery", response_class=HTMLResponse)
async def recovery_submit(request: Request):
    try:
        _owner_row(request, mutate=True)
        fields = await _fields(request, {"code"})
        codes = await run_in_threadpool(second.regenerate, code=fields.get("code", ""))
    except HTTPException as exc:
        return _manage_page(request, local_owner._read() or {}, message=str(exc.detail),
                            status_code=exc.status_code)
    return _step_page(request, view="codes", action="", cancel="", next_href=PAGE, codes=codes,
                      message="Your old recovery codes no longer work. Save these new ones now. Each works "
                              "once, and they are not shown again.")
