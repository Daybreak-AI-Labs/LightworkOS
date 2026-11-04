"""Invite-link accept flow: ``GET/POST /auth/invite/{token}``.

Security mechanics (see :mod:`maverick_dashboard.invites` for the store):

- **Scanner-proof**: the GET only *peeks* (renders a confirmation page); the
  POST consumes. Corporate mail scanners that prefetch every link therefore
  can't burn a single-use invite.
- **CSRF on the consume**: the POST requires a same-origin Origin/Referer
  (this path is exempt from the app-wide auth/CSRF middleware because the
  invitee has no credential yet — the token in the path is the credential).
- **SSO mode** (OIDC browser login configured): accepting requires signing in
  first — the page links to ``/auth/login?return_to=<this invite>`` — and the
  signed session must assert the invited email before the role is bound to
  that principal. SAML-only deployments use ``/saml/login``. The session
  comes from the IdP; the invite never mints one or asks for a passphrase.
- **Local mode** (no IdP): accepting sets the colleague's passphrase (the
  owner's rules, hashing and lockout; see :mod:`local_passphrases`), mints a
  signed ``mvk_session`` cookie for ``user:<invited email>`` and binds the
  role. The passphrase is saved under the same lock that marks the link used,
  so a link is never used up without it: after signing out, the colleague
  signs in again with their email and passphrase.

Every route 404s while ``[dashboard] invites`` is off (fail-closed default).
"""
from __future__ import annotations

import hmac
import logging
from urllib.parse import parse_qs, quote, urlparse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from . import invites, local_passphrases

log = logging.getLogger(__name__)

router = APIRouter()


def require_people_context(request: Request, expected: str | None) -> None:
    """Optional legacy seam; ordinary controls always bind their rendered actor."""
    from .draft_api import context_for

    if expected is not None and (
        len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected)
        or not hmac.compare_digest(expected, context_for(request))
    ):
        raise HTTPException(409, "The account or workspace changed. Reload Users before continuing.")

class _InviteBindFailed(RuntimeError):
    """The link was redeemed, but the original grant/confirmation is uncertain."""


# What each built-in role can do, in the words the People page uses.
ROLE_HELP = {
    "viewer": "look at dashboards and results but change nothing",
    "operator": "run work and approve actions",
    "auditor": "review the activity record and results without changing anything",
    "admin": "manage people, settings and spending",
}


def _page(request: Request, state: str, *, status: int = 200, inv=None, token: str = "",
          message: str = "", principal: str = "", current_role: str | None = None,
          can_open: bool = False) -> HTMLResponse:
    """The invitation page, in the shared public shell (no app nav or session)."""
    from .app import templates

    invite = None
    if inv is not None:
        from maverick.oidc import login_enabled
        from maverick.tenant.registry import get_tenant

        from .saml import saml_enabled

        login_path = "/auth/login" if login_enabled() else "/saml/login" if saml_enabled() else "/auth/login"
        workspace = get_tenant(inv.tenant) if inv.tenant else None
        workspace_name = (workspace.display_name or workspace.id) if workspace else inv.tenant
        invite = {"email": inv.email, "role": inv.role, "role_help": ROLE_HELP.get(inv.role, ""),
                  "workspace": workspace_name, "token": token,
                  "sign_in_href": login_path + "?return_to=" + quote(f"/auth/invite/{token}", safe="/")}
    response = templates.TemplateResponse(
        request, "invite_accept.html",
        {"state": state, "invite": invite, "message": message, "principal": principal,
         "passphrase_sign_in": local_passphrases.available(), "current_role": current_role,
         "can_open": can_open, "grant_confirmed_at": inv.grant_confirmed_at if inv else None},
        status_code=status)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Robots-Tag"] = "noindex"
    # The accept form needs its same-origin Origin header (see local_owner_routes).
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def _gone(request: Request) -> HTMLResponse:
    return _page(request, "gone", status=410)


def _same_origin(request: Request) -> bool:
    """Fail-closed same-origin check for the consuming POST: the accept form is
    served by this host, so a genuine submit carries a matching Origin (or
    Referer). Cross-site or headerless posts are rejected."""
    expected = request.url.netloc
    for header in ("origin", "referer"):
        value = request.headers.get(header)
        if value:
            return urlparse(value).netloc == expected
    return False


def _session_principal(request: Request):
    """The signed-in identity, from whichever session mode is active."""
    if invites.local_login_mode():
        return invites.local_session_principal(request)
    try:
        from .oidc_login import _principal_from_request_session
        return _principal_from_request_session(request)
    except Exception:  # pragma: no cover - login module import never breaks invites
        return None


def _bind_role(principal: str, inv) -> None:
    """Grant the invited role: inside the invite's workspace when it names one
    (a client's first administrator), otherwise dashboard-wide."""
    from . import rbac
    if inv.tenant:
        rbac.set_tenant_role(inv.tenant, principal, inv.role, actor=inv.created_by)
    else:
        rbac.set_role(principal, inv.role, actor=inv.created_by)


def _workspace_invite_allowed(inv, principal: str) -> bool:
    """Recheck a pending workspace grant before it can change membership."""
    if not inv.tenant:
        return True
    from maverick.paths import tenant_by_user_enabled
    from maverick.tenant.registry import get_tenant

    from . import rbac

    workspace = get_tenant(inv.tenant)
    if tenant_by_user_enabled() or workspace is None or not workspace.active:
        return False
    members = rbac.list_tenant_roles(inv.tenant)
    current = members.get(principal)
    invited_permissions = rbac.permissions_for(inv.role)
    if inv.workspace_admin_invite:
        issuer_permissions = rbac.permissions_for(members.get(inv.created_by))
        if ("admin" not in issuer_permissions
                or not invited_permissions.issubset(issuer_permissions)
                or (current is not None
                    and not rbac.permissions_for(current).issubset(issuer_permissions))
                or (principal == inv.created_by and "admin" not in invited_permissions)):
            return False
    if (current is not None and "admin" in rbac.permissions_for(current)
            and "admin" not in invited_permissions
            and sum("admin" in rbac.permissions_for(role) for role in members.values()) <= 1):
        return False
    return True


def _global_invite_issuer_allowed(inv) -> bool:
    """A named installation admin must still have that authority at acceptance.

    Existing records already carry ``created_by``. ``caller_principal`` uses
    ``VerifiedPrincipal.principal`` (``user:<sub>``) for OIDC, SAML and proxy
    identities. Principal-less local and static-token invites have no durable
    person to recheck, so preserve their existing one-time-link contract.
    Scoped workspace issuers are checked by ``_workspace_invite_allowed``.
    """
    issuer = inv.created_by
    if inv.workspace_admin_invite or not issuer.startswith("user:"):
        return True
    from . import auth, rbac, scim_groups

    try:
        if scim_groups.active_for_principal(issuer) is False:
            return False
        permissions = rbac.permissions_for(auth.global_role_for_principal(issuer))
        return "admin" in permissions and rbac.permissions_for(inv.role).issubset(permissions)
    except Exception:
        return False


def _audit_existing_account_refusal(inv) -> None:
    """Record a refused takeover attempt; the refusal stands even if logging fails."""
    try:
        from maverick.audit import audit_event

        audit_event("control_plane_action", agent="dashboard", action="invite_acceptance_refused",
                    actor="invitation-link", invite_id=inv.id, email=inv.email,
                    workspace=inv.tenant or "", created_by=inv.created_by,
                    reason="existing_local_account")
    except Exception:
        log.warning("refused invitation acceptance could not be recorded", exc_info=True)


def _consume_and_bind(token: str, principal=None, *, prepared_passphrase: dict | None = None):
    """Redeem under the role-change fence, including the issuing admin check."""
    from maverick.authority_effects import authority_effect_fence

    with authority_effect_fence():
        from . import rbac
        pending = invites.peek_invite(token)
        if pending is None:
            return None
        target = principal.principal if principal is not None else f"user:{pending.email}"
        if (not rbac.is_known_role(pending.role)
                or (principal is not None and not _matches_invited_account(principal, pending))
                or not _global_invite_issuer_allowed(pending)
                or not _workspace_invite_allowed(pending, target)):
            return None
        def save_passphrase(current):
            if prepared_passphrase is None:
                return
            if prepared_passphrase["email"].casefold() != current.email.casefold():
                raise HTTPException(409, "This invitation changed. Open the link again.")
            # An account may have appeared after the invitation was issued:
            # never set a passphrase over an existing identity.
            if invites.existing_local_account(current.email):
                _audit_existing_account_refusal(current)
                raise HTTPException(409, local_passphrases.ACCOUNT_EXISTS)
            try:
                local_passphrases.store(prepared_passphrase, tenant=current.tenant)
            except HTTPException as exc:
                if exc.status_code == 409:
                    _audit_existing_account_refusal(current)
                raise

        consumed = invites.consume_invite(
            token, used_by=target,
            before_commit=save_passphrase if prepared_passphrase is not None else None,
        )
        if consumed is None:
            return None
        try:
            _bind_role(target, consumed)
            consumed = invites.confirm_grant(consumed.id, target)
        except Exception as exc:
            # Two distinct control-plane stores cannot commit atomically. Burn
            # the bearer token on uncertainty rather than let it grant another
            # identity; tell the person to request a replacement link.
            log.exception("invitation access save or confirmation failed after redemption")
            raise _InviteBindFailed from exc
        return consumed


def _original_receipt(request: Request, token: str):
    """Original accepted actor only; current membership is a separate observation."""
    from maverick.tenant.registry import get_tenant

    from . import rbac

    principal = _session_principal(request)
    inv = invites.lookup_invite(token)
    if principal is None or inv is None or inv.used_at is None or inv.used_by != principal.principal:
        return None
    if (invites.local_login_mode() and principal.principal != f"user:{inv.email}") or (
        not invites.local_login_mode() and not _matches_invited_account(principal, inv)
    ):
        return None
    workspace = get_tenant(inv.tenant) if inv.tenant else None
    current = rbac.get_tenant_role(inv.tenant, inv.used_by) if inv.tenant else rbac.get_stored_role(inv.used_by)
    return inv, current, bool(workspace and workspace.active and current is not None)


def _receipt_page(request: Request, token: str):
    from maverick.authority_effects import authority_effect_fence

    with authority_effect_fence():
        receipt = _original_receipt(request, token)
        if receipt is None:
            return None
        inv, role, available = receipt
        return _page(request, "accepted" if inv.grant_confirmed_at else "unconfirmed",
                     inv=inv, token=token, current_role=role,
                     can_open=available and inv.grant_confirmed_at is not None)


def _matches_invited_account(principal, inv) -> bool:
    """An SSO invite can bind only the email asserted for this login."""
    from .oidc_login import _normalized_invite_email

    claims = principal.claims or {}
    asserted = _normalized_invite_email(claims.get("idp_email"))
    return bool(asserted) and asserted == inv.email.casefold()


def _wrong_account(request: Request, inv, token: str) -> HTMLResponse:
    return _page(request, "wrong_account", status=403, inv=inv, token=token)


def _bind_failed(request: Request) -> HTMLResponse:
    return _page(request, "bind_failed", status=503)


@router.get("/auth/invite/{token}")
async def invite_confirm(request: Request, token: str):
    """Peek-only confirmation page — inert for mail-scanner prefetches."""
    if not invites.invites_enabled():
        return _page(request, "not_found", status=404)
    inv = invites.peek_invite(token)
    if inv is None:
        return _receipt_page(request, token) or _gone(request)
    from . import rbac
    if not rbac.is_known_role(inv.role):
        return _page(request, "unavailable", status=410, inv=inv, token=token,
                     message="This invitation's role is no longer available. The link has not been used. Ask your administrator for a new invitation.")
    if invites.local_login_mode():
        return _page(request, "local", inv=inv, token=token)
    principal = _session_principal(request)
    if principal is None:
        # SSO mode, not signed in yet: sign in first, then land back here.
        return _page(request, "sso_sign_in", inv=inv, token=token)
    if not _matches_invited_account(principal, inv):
        return _wrong_account(request, inv, token)
    return _page(request, "sso_accept", inv=inv, token=token, principal=inv.email)


async def _passphrase_fields(request: Request) -> tuple[str, str]:
    """The two passphrase boxes from the accept form (bounded, one value each)."""
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/x-www-form-urlencoded":
        raise HTTPException(415, "Open the invitation link and submit the form from that page.")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 8192:
            raise HTTPException(413, "The form is larger than this page sends.")
    data = parse_qs(bytes(body).decode("utf-8"), max_num_fields=3, keep_blank_values=True)
    if set(data) - {"password", "password2"} or any(len(v) != 1 for v in data.values()):
        raise HTTPException(422, "Submit one value for each field.")
    password, password2 = data.get("password", [""])[0], data.get("password2", [""])[0]
    if password != password2:
        raise HTTPException(422, "The passphrases do not match. Type the same passphrase in both boxes.")
    return password, password2


async def _accept_locally(request: Request, token: str) -> HTMLResponse | RedirectResponse:
    """Local mode: set the passphrase, use up the link, sign the browser in."""
    inv = invites.peek_invite(token)
    if inv is None:
        return _receipt_page(request, token) or _gone(request)
    try:
        password, _ = await _passphrase_fields(request)
        # Slow on purpose (scrypt): off the event loop, before the link is used.
        prepared = await run_in_threadpool(local_passphrases.prepare, inv.email, password)
    except (UnicodeError, ValueError):
        return _page(request, "local", status=422, inv=inv, token=token,
                     message="Check the passphrase and try again.")
    except HTTPException as exc:
        return _page(request, "local", status=exc.status_code, inv=inv, token=token,
                     message=str(exc.detail))
    try:
        used = await run_in_threadpool(_consume_and_bind, token, prepared_passphrase=prepared)
    except HTTPException as exc:
        return _page(request, "local", status=exc.status_code, inv=inv, token=token,
                     message=str(exc.detail))
    except _InviteBindFailed:
        return _bind_failed(request)
    if used is None:
        return _gone(request)
    log.info("invite accepted (local): %s as %s", used.email, used.role)
    response = RedirectResponse(f"/auth/invite/{token}", status_code=303)
    from .oidc_login import _cookie_secure, _set_cookie
    _set_cookie(response, "mvk_session", invites.mint_local_session(used.email, request=request),
                max_age=invites.session_ttl_seconds(),
                secure=_cookie_secure(request))
    return response


@router.post("/auth/invite/{token}")
async def invite_accept(request: Request, token: str):
    """Consume the invite: bind the role and (in local mode) sign the browser in."""
    if not invites.invites_enabled():
        return _page(request, "not_found", status=404)
    if not _same_origin(request):
        return _page(request, "blocked", status=400)
    if invites.local_login_mode():
        return await _accept_locally(request, token)
    principal = _session_principal(request)
    if principal is None:
        return _page(request, "sign_in_required", status=401)
    pending = invites.peek_invite(token)
    if pending is None:
        return _receipt_page(request, token) or _gone(request)
    if not _matches_invited_account(principal, pending):
        return _wrong_account(request, pending, token)
    try:
        inv = await run_in_threadpool(_consume_and_bind, token, principal)
    except _InviteBindFailed:
        return _bind_failed(request)
    if inv is None:
        return _gone(request)
    log.info("invite accepted (sso): %s bound to %s (invite for %s)",
             principal.principal, inv.role, inv.email)
    return RedirectResponse(f"/auth/invite/{token}", status_code=303)


def _open_workspace(request: Request, token: str):
    from maverick.authority_effects import authority_effect_fence

    from .api import select_active_tenant

    with authority_effect_fence():
        receipt = _original_receipt(request, token)
        if receipt is None:
            return _gone(request)
        inv, role, available = receipt
        if not available or inv.grant_confirmed_at is None:
            return _page(request, "accepted" if inv.grant_confirmed_at else "unconfirmed", inv=inv, token=token,
                         current_role=role, message="This workspace is not currently available to your account.")
        import os

        # An installation pinned to the invited workspace is already in it.
        if inv.tenant and os.environ.get("MAVERICK_TENANT", "").strip() == inv.tenant:
            return RedirectResponse("/", status_code=303)
        try:
            select_active_tenant(request, inv.tenant)
        except HTTPException as exc:
            return _page(request, "accepted", status=exc.status_code, inv=inv, token=token, current_role=role,
                         message="This workspace could not be opened. Your installation may use a fixed workspace, or your access changed. Ask your administrator.")
        return RedirectResponse("/", status_code=303)


@router.post("/auth/invite/{token}/workspace")
async def invite_open_workspace(request: Request, token: str):
    """Explicit navigation after confirmed acceptance; never repeat a grant."""
    if not invites.invites_enabled():
        return _page(request, "not_found", status=404)
    if not _same_origin(request):
        return _page(request, "blocked", status=400)
    return await run_in_threadpool(_open_workspace, request, token)


@router.get("/api/v1/users/workspace-context")
def workspace_people_context(request: Request):
    """Protected form handoff contains no invitation links or roster material."""
    from maverick.authority_effects import authority_effect_fence

    from . import auth
    from .admin_pages import _workspace_options
    from .draft_api import context_for

    with authority_effect_fence():
        auth.require_permission(request, "admin")
        options, _ = _workspace_options(request)
        if not options and not auth.has_global_permission(request, "admin"):
            raise HTTPException(403, "You no longer manage a workspace.")
        return {"context": context_for(request)}
