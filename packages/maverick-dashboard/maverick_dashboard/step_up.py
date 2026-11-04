"""Step-up: sensitive actions need a recent second factor.

While ``[auth.mfa] require`` is on, the operations listed in
:data:`SENSITIVE_OPERATIONS` are allowed only from a named sign-in whose
second factor is no older than ``[auth.mfa] step_up_minutes`` (default 15).
Anything else gets a 403 with one plain sentence and a link that signs the
person in again (the OIDC request then carries ``prompt=login`` and the SAML
request ``ForceAuthn``, so the provider asks for the authenticator again
instead of reusing its session).

Where it does not apply, deliberately:

* no named sign-in (auth-off local mode, the static server token): there is
  no principal to hold a second factor, and the request already passed the
  boundary that mode allows;
* ``require`` off: step-up is the freshness half of the second-factor policy
  and is meaningless without it.

Routes call :func:`require_recent_mfa` after their permission check. Keep
this list in one place: it is what the security overview documents.
"""
from __future__ import annotations

from urllib.parse import quote

from fastapi import HTTPException, Request

SENSITIVE_OPERATIONS: dict[str, str] = {
    "change_role": "Changing a person's role or removing their access",
    "remove_spending_limit": "Removing a spending limit",
    "clear_emergency_stop": "Turning off the emergency stop",
    "rotate_keys": "Rotating signing or workspace keys",
    "change_auth_settings": "Changing sign-in, administrator or key-service settings",
    "delete_workspace": "Deleting a workspace",
    "restore_workspace": "Restoring a removed workspace",
    "revoke_sessions": "Signing other devices or people out",
    "reset_passphrase": "Resetting a colleague's passphrase",
}

STEP_UP_MESSAGE = (
    "This action needs a recent sign-in with your authenticator. Sign in again, "
    "then try again."
)


class StepUpRequired(HTTPException):
    """403 carrying the plain sentence and the re-authentication link."""

    def __init__(self, reauthenticate: str) -> None:
        super().__init__(status_code=403, detail=STEP_UP_MESSAGE,
                         headers={"X-Reauthenticate": reauthenticate})
        self.reauthenticate = reauthenticate


def reauthenticate_url(request: Request | None) -> str:
    """Where to send the person to sign in again and come back."""
    return_to = "/"
    if request is not None:
        return_to = request.url.path
        if request.method == "GET" and request.url.query:
            return_to = f"{return_to}?{request.url.query}"
    encoded = quote(return_to, safe="")
    try:
        from maverick.oidc import login_enabled

        if login_enabled():
            return f"/auth/login?fresh=1&return_to={encoded}"
    except Exception:
        pass
    try:
        from .saml import saml_enabled

        if saml_enabled():
            return f"/saml/login?fresh=1&return_to={encoded}"
    except Exception:
        pass
    return "/auth/logout"


def applies(request: Request) -> bool:
    """Whether step-up gates this request at all (see the module note)."""
    from . import auth
    from .mfa_policy import require_mfa

    if auth.caller_principal(request) is None:
        return False
    return require_mfa()


def require_recent_mfa(request: Request, operation: str) -> None:
    """Raise :class:`StepUpRequired` unless the caller's second factor is fresh."""
    if operation not in SENSITIVE_OPERATIONS:
        raise ValueError(f"unknown sensitive operation {operation!r}")
    if not applies(request):
        return
    from .mfa_policy import fresh_enough, principal_mfa

    principal = getattr(getattr(request, "state", None), "principal", None)
    proved, when = principal_mfa(principal)
    if proved and fresh_enough(when):
        return
    raise StepUpRequired(reauthenticate_url(request))


__all__ = [
    "SENSITIVE_OPERATIONS",
    "STEP_UP_MESSAGE",
    "StepUpRequired",
    "applies",
    "reauthenticate_url",
    "require_recent_mfa",
]
