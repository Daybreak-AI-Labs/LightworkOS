"""Loopback-only owner bootstrap, and passphrase sign-in; no external identity calls.

The owner sets up and signs in only on the computer running Lightwork. Invited
colleagues (see :mod:`local_passphrases`) sign in on the same page from any
computer, with the passphrase they chose when they accepted their invitation.
"""
from __future__ import annotations

from urllib.parse import parse_qs

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import local_owner, local_passphrases
from .local_owner_second_factor import Challenge
from .rbac import ROSTER_RECOVERY, RosterMissingError

router = APIRouter()

ROSTER_MISSING = f"Sign-in is unavailable because the role list is missing. {ROSTER_RECOVERY}"


def _form(request: Request, *, setup: bool, message="", status=200):
    title = "Set up the owner of this installation" if setup else "Sign in to Lightwork"
    explanation = (
        "The owner manages this installation: they invite colleagues, set roles and change settings. "
        "Saving turns off anonymous administrator access and turns on named sign-in. "
        "Your email is only a label for this account; Lightwork does not verify it or send a message. "
        "Keep the passphrase somewhere safe: there is no reset by email."
        if setup else "Use your email and passphrase. Invited colleagues chose their passphrase when "
        "they accepted their invitation. The owner of this installation signs in on the computer "
        "running Lightwork."
    )
    from .app import templates

    response = templates.TemplateResponse(
        request, "local_owner.html",
        {"title": title, "explanation": explanation, "message": message, "setup": setup},
        status_code=status)
    response.headers["Cache-Control"] = "no-store"
    # Native browser form submissions need their same-origin Origin header.
    # no-referrer makes Chromium send Origin: null and defeats the CSRF check.
    # External sites still receive no referrer under this policy.
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def _on_this_computer(request: Request) -> bool:
    try:
        local_owner._local(request)
    except HTTPException:
        return False
    return True


@router.get("/auth/local-owner", response_class=HTMLResponse)
def owner_form(request: Request):
    local_owner._local(request)
    if local_owner.claimed():
        return RedirectResponse("/auth/local-login", status_code=303)
    if not local_owner.available(request):
        return _form(request, setup=True, message="Local first-owner setup is unavailable under this installation's current identity policy.", status=409)
    return _form(request, setup=True)


@router.get("/auth/local-login", response_class=HTMLResponse)
def login_form(request: Request):
    if local_passphrases.available():
        # Colleagues sign in here from any computer.
        if not local_owner.claimed() and _on_this_computer(request) and local_owner.available(request):
            return RedirectResponse("/auth/local-owner", status_code=303)
        return _form(request, setup=False)
    local_owner._local(request)
    local_owner._policy()
    if not local_owner.claimed():
        return RedirectResponse("/auth/local-owner", status_code=303)
    return _form(request, setup=False)


def _sign_in(request: Request, email: str, password: str, colleagues: bool):
    """The owner on this computer, otherwise an invited colleague.

    Returns the session token, or the owner's second-step challenge.
    """
    if not colleagues:
        return local_owner.login(request, email=email, password=password)
    if _on_this_computer(request) and local_owner.claimed() and local_passphrases.owner_of(email):
        try:
            return local_owner.login(request, email=email, password=password)
        except HTTPException as exc:
            if exc.status_code == 401:  # one answer for every failed sign-in
                raise HTTPException(401, local_passphrases.NOT_ACCEPTED) from None
            raise
    return local_passphrases.login(request, email=email, password=password)


async def _submit(request, *, setup):
    colleagues = not setup and local_passphrases.available()
    try:
        if not setup:
            # Per client address, before anything is read or hashed.
            local_passphrases.limit_attempts(request)
        if colleagues:
            local_passphrases.require_same_origin(request)
        else:
            local_owner._local(request, mutate=True)
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/x-www-form-urlencoded":
            raise HTTPException(415, "Submit the form from this page.")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 16384:
                raise HTTPException(413, "The owner form exceeds its supported size.")
        data = parse_qs(bytes(body).decode("utf-8"), max_num_fields=5, keep_blank_values=True)
        if set(data) - {"email", "password", "password2", "confirm"} or any(len(v) != 1 for v in data.values()):
            raise HTTPException(422, "Submit one value for each field.")
        fields = {k: v[0] for k, v in data.items()}
        # A typo in a passphrase nobody can reset locks the owner out: the
        # setup form asks for it twice and refuses a mismatch.
        if setup and "password2" in fields and fields["password2"] != fields.get("password", ""):
            raise HTTPException(422, "The passphrases do not match. Type the same passphrase in both boxes.")
        # Slow passphrase verification runs off the ASGI event loop.
        from starlette.concurrency import run_in_threadpool
        if setup:
            token = await run_in_threadpool(local_owner.enroll, request, email=fields.get("email", ""),
                                            password=fields.get("password", ""), confirm=fields.get("confirm") == "yes")
        else:
            token = await run_in_threadpool(_sign_in, request, fields.get("email", ""),
                                            fields.get("password", ""), colleagues)
        if isinstance(token, Challenge):
            # The owner's authenticator app is set up or asked for before any session exists.
            from .local_owner_mfa_routes import challenge_response, safe_return_to
            return challenge_response(request, token, return_to=(
                "" if setup else safe_return_to(request.query_params.get("return_to"))))
        from .invites import session_ttl_seconds
        from .oidc_login import _cookie_secure, _set_cookie
        # The owner lands on Get started; a colleague lands on their home page.
        owner_signed_in = setup or not colleagues or local_passphrases.owner_of(fields.get("email", ""))
        # Signing in again after a sign-in ended returns to that page.
        from .oidc_login import _is_safe_return_to

        return_to = request.query_params.get("return_to")
        landing = return_to if (not setup and _is_safe_return_to(return_to)
                                and not return_to.startswith("/auth/")) else (
            "/start" if owner_signed_in else "/")
        response = RedirectResponse(landing, status_code=303)
        _set_cookie(response, "mvk_session", token, max_age=session_ttl_seconds(), secure=_cookie_secure(request))
        response.headers["Cache-Control"] = "no-store"
        return response
    except HTTPException as exc:
        response = _form(request, setup=setup, message=str(exc.detail), status=exc.status_code)
        if exc.status_code == 429:
            response.headers["Retry-After"] = "60"
        return response
    except (UnicodeError, ValueError):
        return _form(request, setup=setup, message="Check the submitted form values.", status=422)
    except RosterMissingError:
        return _form(request, setup=setup, message=ROSTER_MISSING, status=503)
    except Exception:
        if not setup and colleagues:
            return _form(request, setup=False, message=local_passphrases.UNAVAILABLE, status=503)
        return _form(request, setup=setup, message="Owner setup could not finish. If ownership was saved, sign in with the same email and passphrase to retry safely.", status=503)


@router.post("/auth/local-owner", response_class=HTMLResponse)
async def owner_submit(request: Request):
    return await _submit(request, setup=True)


@router.post("/auth/local-login", response_class=HTMLResponse)
async def login_submit(request: Request):
    return await _submit(request, setup=False)
