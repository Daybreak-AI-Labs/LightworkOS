"""Resetting a colleague's forgotten passphrase, and the one-time link it gives.

Who may reset: only the installation owner (``local_owner``). Never a
workspace administrator, someone given the Admin role, or an administrator
listed in ``[dashboard] admins``: whoever resets a passphrase chooses who can
set the next one, so this is an account takeover in the wrong hands, and that
list can be edited in Settings by anyone holding the Admin role, so being on
it proves nothing. The owner's own passphrase is never reset here (owner
recovery stays on this computer). The route also needs a recent second factor
where step-up applies, a same-origin form post and an explicit confirmation.

What a reset does, in this order:

1. checks the request, then writes an audit row naming who reset whom. If the
   activity log refuses it, nothing has changed: the passphrase and every
   session stay as they were and no link exists;
2. records a one-time link (only a SHA-256 of its token is stored) bound to
   that exact account: its installation role, workspace memberships,
   department access and administrator status, including any the identity
   provider's groups confer;
3. removes the colleague's passphrase, so it no longer signs in;
4. ends every session they hold: the Sessions record and the revocation
   epoch, which also stops older cookies and bearers.

The link (``/auth/invite/reset/<token>``, under the same token-is-the-
credential exemption as invitation links) works once, for one hour, and only
sets a passphrase for that account. It mints no session, cannot change a role
or membership, and is refused, and used up, if the account changed since the
reset or its issuer no longer holds that authority. Completing it is audited
before the passphrase is saved. The person signs in normally afterwards.

A person who has access here but no passphrase (a role assigned on the Users
page, a workspace membership, or a place in ``[dashboard] admins``) cannot be
invited, because an invitation never replaces what already exists, and has
nothing to reset. The same people may give them a first-passphrase link, by the
same route, step-up, audit row and account binding; the only difference is
that there is no passphrase to remove.

Store: ``~/.maverick/dashboard-passphrase-resets.json`` (0600). Any
unreadable or malformed store fails closed. Each new reset replaces the
person's earlier link; a reset whose link expired or was refused stays listed
until the person has a passphrase again, so the owner can issue another. Once
they have one, the next reset issued here removes that record; a completed
reset is kept for 30 days.
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
import threading
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from maverick import file_lock
from maverick.paths import MAX_TENANT_SEGMENT_LENGTH, maverick_home
from starlette.concurrency import run_in_threadpool

from . import local_passphrases

router = APIRouter()

_LOCK = threading.RLock()
_SCHEMA = "lightwork.passphrase-resets.v1"
_MAX_RECORDS = 5000
_MAX_BYTES = 4 * 1024 * 1024
_KEEP_SECONDS = 30 * 86400  # completed resets are pruned after this
_PREFIX = "pwr_"
RESET_TTL_SECONDS = 3600

ONLY_OWNER = "Only the installation owner can reset a passphrase."
OWNER_REFUSED = "The installation owner's passphrase cannot be reset from the Users page."
NO_PASSPHRASE = ("This person has no passphrase and no access here, so there is nothing to reset or "
                 "give. Invite them from the Users page instead.")
UNAVAILABLE = "Passphrase resets are unavailable right now. Ask your administrator to check Lightwork."
CHANGED = ("The access of this account, or of the person who reset it, changed after the reset, so "
           "this link no longer works. Ask the installation owner to reset your passphrase again.")


def path():
    return maverick_home() / "dashboard-passphrase-resets.json"


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _valid(key: object, row: object) -> bool:
    if not isinstance(key, str) or len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        return False
    if not isinstance(row, dict) or set(row) != {
            "email", "tenant", "binding", "created_by", "created_at", "expires_at", "used_at", "outcome",
            "first"}:
        return False
    return (isinstance(row["email"], str) and "@" in row["email"] and len(row["email"]) <= 320
            and row["email"] == row["email"].strip().lower()
            and isinstance(row["tenant"], str) and len(row["tenant"]) <= MAX_TENANT_SEGMENT_LENGTH
            and isinstance(row["binding"], str) and len(row["binding"]) == 64
            and isinstance(row["created_by"], str) and row["created_by"].startswith("user:")
            and len(row["created_by"]) <= 1024
            and _number(row["created_at"]) and _number(row["expires_at"])
            and (row["used_at"] is None or _number(row["used_at"]))
            and isinstance(row["first"], bool)
            and row["outcome"] in {"", "set", "refused"}
            and (row["outcome"] == "") == (row["used_at"] is None))


def _read() -> dict[str, dict]:
    try:
        file_lock.ensure_private_file(path())
        if path().stat().st_size > _MAX_BYTES:
            raise ValueError("passphrase reset store exceeds its bound")
        data = json.loads(file_lock.atomic_read_text(path()))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise HTTPException(503, UNAVAILABLE) from exc
    resets = data.get("resets") if isinstance(data, dict) else None
    if (not isinstance(data, dict) or data.get("schema") != _SCHEMA
            or not isinstance(resets, dict) or len(resets) > _MAX_RECORDS
            or not all(_valid(key, row) for key, row in resets.items())):
        raise HTTPException(503, UNAVAILABLE)
    return resets


def _write(resets: dict[str, dict]) -> None:
    file_lock.atomic_write_text(path(), json.dumps({"schema": _SCHEMA, "resets": resets},
                                                    sort_keys=True), mode=0o600)


def _locked(*, fence: bool = True):
    from contextlib import ExitStack

    from maverick.authority_effects import authority_effect_fence

    file_lock.ensure_private_directory(maverick_home())
    with ExitStack() as stack:
        # Role changes hold the same fence, so the account cannot change
        # between the binding check and the write. Reads skip it.
        if fence:
            stack.enter_context(authority_effect_fence())
        stack.enter_context(_LOCK)
        stack.enter_context(file_lock.cross_process_lock(path(), strict=True))
        return stack.pop_all()


def _binding(email: str) -> str:
    """A fingerprint of what the account may do. A link stops working once it changes.

    It covers stored and derived authority alike: the role and departments the
    person actually holds (so an IdP group that grants either changes it), and
    whether the IdP has bound them at all, as well as the stored role,
    memberships and explicit department grant."""
    from maverick.suite_grants import get_grant, granted_suites, is_admin_principal

    from . import auth, rbac, scim_groups

    principal = "user:" + email
    try:
        grant = get_grant(principal)
        effective = granted_suites(principal)  # explicit, then IdP groups, then the default
        state = {"role": rbac.get_stored_role(principal),
                 "effective_role": auth.global_role_for_principal(principal),
                 "idp_record": scim_groups.active_for_principal(principal),
                 "workspaces": rbac.tenant_memberships(principal),
                 "departments": None if grant is None else sorted(grant),
                 "effective_departments": None if effective is None else sorted(effective),
                 "installation_admin": is_admin_principal(principal),
                 "owner": local_passphrases.owner_of(email)}
    except HTTPException:
        raise
    except Exception as exc:  # unreadable access state: change nothing
        raise HTTPException(503, UNAVAILABLE) from exc
    return hashlib.sha256(json.dumps(state, sort_keys=True).encode("utf-8")).hexdigest()


def _owner_principal() -> str | None:
    from . import local_owner

    row = local_owner._read()  # unreadable owner record: 503
    return "user:" + row["email"] if row is not None and row["status"] == "ready" else None


def _authority(issuer: str) -> str | None:
    """``"owner"`` when ``issuer`` is the installation owner and may reset
    passphrases now; None for anyone else."""
    from . import auth, rbac

    if not issuer.startswith("user:") or issuer != _owner_principal():
        return None
    # The owner keeps this power only while still an administrator.
    role = auth.global_role_for_principal(issuer)
    return "owner" if "admin" in rbac.permissions_for(role) else None


def _allowed(authority: str | None) -> bool:
    return authority == "owner"


def actor(request: Request) -> str:
    """The caller, when allowed to reset passphrases at all; 403 for anyone else.

    Callers check ``auth.require_global_permission(request, "admin")`` first."""
    from . import auth

    caller = auth.caller_principal(request) or ""
    if _authority(caller) is None:
        raise HTTPException(403, ONLY_OWNER)
    return caller


def can_reset(request: Request) -> str | None:
    """The caller, when the Users page offers them the reset; else None."""
    try:
        from . import auth

        if not local_passphrases.available() or not auth.has_global_permission(request, "admin"):
            return None
        return actor(request)
    except HTTPException:
        return None


def _unresolved(resets: dict[str, dict], email: str) -> bool:
    return any(row["email"] == email and row["outcome"] != "set" for row in resets.values())


def pending_for(email: str) -> bool:
    """Whether ``email`` is waiting for a new passphrase after a reset."""
    with _locked(fence=False):
        return _unresolved(_read(), (email or "").strip().lower())


def _emails_with_access() -> set[str]:
    """Everyone who holds access here under their own email: an installation
    role, a workspace membership or a place in ``[dashboard] admins``."""
    from maverick.suite_grants import admin_principals

    from . import rbac

    try:
        principals = set(rbac.list_users()) | rbac.tenant_member_principals() | set(admin_principals())
    except rbac.RbacStoreError as exc:  # a lost or damaged role list: offer nothing
        raise HTTPException(503, UNAVAILABLE) from exc
    emails = {principal.removeprefix("user:") for principal in principals if principal.startswith("user:")}
    return {email for email in emails if _is_email(email)}


def _is_email(email: str) -> bool:
    return (0 < len(email) <= 320 and "@" in email and email == email.strip().lower()
            and not any(c.isspace() for c in email))


def accounts(caller: str) -> list[dict]:
    """The people ``caller`` may give a passphrase link, sorted:
    ``[{email, has_passphrase, waiting, first}]``.

    ``has_passphrase`` people can be reset. ``waiting`` people were reset (or
    given a first link) and have not yet chosen one. ``first`` people have
    access but have never had a passphrase."""
    with _locked(fence=False):
        resets = _read()
    current = set(local_passphrases.emails())
    waiting = {row["email"] for row in resets.values() if row["outcome"] != "set"} - current
    first = _emails_with_access() - current - waiting
    owner, authority = _owner_principal(), _authority(caller)
    return [{"email": email, "has_passphrase": email in current, "waiting": email in waiting,
             "first": email in first}
            for email in sorted(current | waiting | first)
            if "user:" + email != owner and _allowed(authority)]


def _first_passphrase_tenant(email: str) -> str | None:
    """The workspace to remember for a first passphrase, or None when the
    person has no access to give one to. Installation access needs none; a
    person with workspace roles only signs in through their first workspace."""
    from maverick.suite_grants import is_admin_principal

    from . import rbac

    principal = "user:" + email
    try:
        stored = rbac.get_stored_role(principal)
        memberships = rbac.tenant_memberships(principal)
        administrator = is_admin_principal(principal)
    except Exception as exc:  # unreadable access state: change nothing
        raise HTTPException(503, UNAVAILABLE) from exc
    if stored is None and not memberships and not administrator:
        return None
    return "" if stored is not None or not memberships else next(iter(memberships))


def _prune(resets: dict[str, dict], now: float, current: set[str]) -> None:
    """Drop completed resets past the keep period, and any reset whose link
    expired or was refused once its person (``current``: everyone with a
    passphrase) has a passphrase again and so is no longer listed as waiting."""
    for key in [key for key, row in resets.items()
                if (row["outcome"] == "set" and row["used_at"] < now - _KEEP_SECONDS)
                or (row["outcome"] != "set" and row["email"] in current
                    and (row["outcome"] or row["expires_at"] <= now))]:
        del resets[key]


def issue(request: Request, email: str) -> tuple[str, dict]:
    """Reset ``email``'s passphrase, or give a person who has none a first link.

    Returns ``(token, record)``; see the module note."""
    from . import session_registry
    from .audit_actions_api import _audit_event
    from .session_revocation import RevocationStoreError, revoke_principal

    caller = actor(request)
    email = (email or "").strip().lower()
    if not _is_email(email):
        raise HTTPException(404, NO_PASSPHRASE)
    token = _PREFIX + secrets.token_urlsafe(32)
    with _locked():
        if local_passphrases.owner_of(email):
            raise HTTPException(403, OWNER_REFUSED)
        authority = _authority(caller)
        if not _allowed(authority):
            raise HTTPException(403, ONLY_OWNER)
        resets = _read()
        now = time.time()
        current = set(local_passphrases.emails())  # read before revoke() holds that store
        record = {"email": email, "tenant": "", "binding": _binding(email), "created_by": caller,
                  "created_at": now, "expires_at": now + RESET_TTL_SECONDS, "used_at": None, "outcome": "",
                  "first": False}

        def save_link(row: dict | None) -> None:
            earlier = [key for key, item in resets.items() if item["email"] == email]
            waiting = _unresolved(resets, email)
            if row is not None:
                record["tenant"] = row["tenant"]
            elif waiting:  # the passphrase went with an earlier reset: keep its workspace
                latest = max((resets[key] for key in earlier), key=lambda item: item["created_at"])
                record["tenant"], record["first"] = latest["tenant"], latest["first"]
            else:  # access but no passphrase: a first link, if there is access to give one to
                tenant = _first_passphrase_tenant(email)
                if tenant is None:
                    raise HTTPException(404, NO_PASSPHRASE)
                record["tenant"], record["first"] = tenant, True
            for key in earlier:  # the earlier link stops working
                del resets[key]
            _prune(resets, now, current)
            if len(resets) >= _MAX_RECORDS:
                raise HTTPException(409, "Too many passphrase resets are waiting. Try again later.")
            resets[_digest(token)] = record
            # The row comes before anything is saved or removed (complete() does
            # the same): a refusal leaves the person signed in with their
            # passphrase, and nobody can be locked out without a record of who did it.
            _audit_event(request, "passphrase_reset_issued", principal="user:" + email, email=email,
                         reset_by=caller, expires_at=record["expires_at"],
                         passphrase_removed=row is not None, first_passphrase=record["first"])
            _write(resets)

        local_passphrases.revoke(email, before_commit=save_link)
        principal = "user:" + email
        try:
            # The epoch ends every cookie and bearer issued before now, tracked
            # or not; the Sessions record then shows each session as ended.
            revoke_principal(email)
            session_registry.revoke_all(principal, by=caller)
        except (RevocationStoreError, session_registry.SessionStoreError) as exc:
            raise HTTPException(503, "The session record cannot be read right now. "
                                     "Reset the passphrase again in a moment.") from exc
    return token, dict(record)


def peek(token: str) -> dict | None:
    """The reset a link names, while it can still be used (read only)."""
    if not isinstance(token, str) or not token.startswith(_PREFIX) or len(token) > 100:
        return None
    with _locked(fence=False):
        record = _read().get(_digest(token))
    if record is None or record["outcome"] or record["expires_at"] <= time.time():
        return None
    return dict(record)


class AccountChanged(HTTPException):
    """The account (or the issuer's authority) changed since the reset."""

    def __init__(self) -> None:
        super().__init__(409, CHANGED)


def _audit_link(action: str, record: dict, **fields) -> None:
    from maverick.audit import AuditRefused, audit_event

    try:
        audit_event("control_plane_action", agent="dashboard", action=action,
                    actor="passphrase-reset-link", principal="user:" + record["email"],
                    email=record["email"], reset_by=record["created_by"], **fields)
    except AuditRefused as exc:
        raise HTTPException(503, "The activity log refused this change.") from exc


def complete(token: str, prepared: dict) -> dict:
    """Use a reset link once: save the new passphrase for exactly that account."""
    with _locked():
        resets = _read()
        record = resets.get(_digest(token))
        now = time.time()
        if record is None or record["outcome"] or record["expires_at"] <= now:
            raise HTTPException(410, "This reset link is invalid, expired or already used.")
        if prepared["email"] != record["email"]:
            raise HTTPException(409, "This reset link changed. Open it again.")
        if (_binding(record["email"]) != record["binding"]
                or not _allowed(_authority(record["created_by"]))):
            record.update(used_at=now, outcome="refused")
            _write(resets)
            try:
                _audit_link("passphrase_reset_refused", record, reason="account_changed")
            except HTTPException:
                pass  # the refusal stands even if the log refuses it
            raise AccountChanged
        if local_passphrases.has_account(record["email"]):
            raise HTTPException(409, local_passphrases.ACCOUNT_EXISTS)
        _audit_link("passphrase_reset_completed", record)
        local_passphrases.store(prepared, tenant=record["tenant"])  # 409 if one appeared since
        record.update(used_at=now, outcome="set")
        _write(resets)
        return dict(record)


# ---------------------------------------------------------------- the page

def _reset_by(created_by: str) -> str:
    try:
        owner = _owner_principal()
    except HTTPException:
        owner = None
    who = created_by.removeprefix("user:")
    return (f"the installation owner ({who})" if created_by == owner
            else f"an administrator ({who})")


def _page(request: Request, state: str, *, status: int = 200, record: dict | None = None,
          message: str = "") -> HTMLResponse:
    """The reset page, in the shared public shell (no app nav or session)."""
    from .app import templates

    reset = None
    if record is not None:
        reset = {"email": record["email"], "reset_by": _reset_by(record["created_by"]),
                 "created_at": record["created_at"], "expires_at": record["expires_at"],
                 "first": record["first"]}
    response = templates.TemplateResponse(
        request, "passphrase_reset.html", {"state": state, "reset": reset, "message": message},
        status_code=status)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Robots-Tag"] = "noindex"
    # The form needs its same-origin Origin header (see local_owner_routes).
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def _enabled() -> bool:
    from . import invites

    return invites.invites_enabled() and local_passphrases.available()


@router.get("/auth/invite/reset/{token}")
async def passphrase_reset_page(request: Request, token: str):
    """Peek only: a mail scanner opening the link cannot use it up."""
    if not _enabled():
        return _page(request, "not_found", status=404)
    record = await run_in_threadpool(peek, token)
    if record is None:
        return _page(request, "gone", status=410)
    return _page(request, "form", record=record)


@router.post("/auth/invite/reset/{token}")
async def passphrase_reset_submit(request: Request, token: str):
    """Set the new passphrase. No session is minted: the person signs in next."""
    from .invite_routes import _passphrase_fields, _same_origin

    if not _enabled():
        return _page(request, "not_found", status=404)
    if not _same_origin(request):
        return _page(request, "blocked", status=400)
    record = await run_in_threadpool(peek, token)
    if record is None:
        return _page(request, "gone", status=410)
    try:
        password, _ = await _passphrase_fields(request)
        # Slow on purpose (scrypt): off the event loop, before the link is used.
        prepared = await run_in_threadpool(local_passphrases.prepare, record["email"], password)
        await run_in_threadpool(complete, token, prepared)
    except (UnicodeError, ValueError):
        return _page(request, "form", status=422, record=record,
                     message="Check the passphrase and try again.")
    except AccountChanged:
        return _page(request, "changed", status=409)
    except HTTPException as exc:
        if exc.status_code == 410:
            return _page(request, "gone", status=410)
        return _page(request, "form", status=exc.status_code, record=record, message=str(exc.detail))
    return _page(request, "done", record=record)


__all__ = ["RESET_TTL_SECONDS", "AccountChanged", "accounts", "actor", "can_reset", "complete",
           "issue", "peek", "pending_for", "router"]
