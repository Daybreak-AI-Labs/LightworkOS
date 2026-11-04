"""Email invite links — how a client admin adds people to the dashboard.

An **invite** is a single-use, expiring link an admin mints for a colleague's
email address with a pre-assigned RBAC role. It solves onboarding for both
customer postures:

- **SSO deployments** (Azure AD/Entra, Okta, … via the built-in OIDC login):
  the invitee clicks the link, signs in with their company IdP, and the invite
  binds their verified principal to the invited role in the RBAC roster — no
  admin copy-pasting opaque ``user:<sub>`` strings.
- **No-IdP deployments** (the "just get us working" path): accepting the
  invite itself signs the browser in — a signed ``mvk_session`` cookie for
  ``user:<email>``, minted with a locally-held secret. The link IS the
  credential (a magic link), so treat it like a password reset email.

Default **OFF** (``[dashboard] invites = true`` / ``MAVERICK_DASHBOARD_INVITES``
to enable) and fail-closed: every route 404s while disabled, so an unconfigured
deployment is byte-identical. Tokens are stored **hashed** (sha256) — the store
never contains a usable link — and consumption is atomic under the same
cross-process lock discipline as the RBAC roster, so a link can't be redeemed
twice. The accept flow is GET-shows-confirmation / POST-consumes, so a mail
scanner prefetching the link cannot burn it, and the POST is same-origin-gated.

Store: ``~/.maverick/dashboard-invites.json`` (0600) — control-plane data,
one global file, like ``dashboard-users.json``.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import string
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

INVITE_TTL_HOURS = 7 * 24          # default link lifetime
INVITE_EXPIRIES = {"1_hour": 1, "1_day": 24, "7_days": 168, "30_days": 720}
LOCAL_SESSION_DAYS = 30            # no-IdP session lifetime (then sign in with the passphrase)
_MAX_PENDING = 500                 # cap the store; an admin never needs more

_INVITES_LOCK = threading.Lock()


class InviteStoreError(RuntimeError):
    """Invite state exists but cannot be read or validated safely."""


class ExistingAccountError(ValueError):
    """A local invitation would take over an identity that already exists here."""


class InviteRateLimited(RuntimeError):
    """A workspace administrator has made too many invitations in a short time."""


# A workspace administrator is told only that an invitation could not be made,
# but an invitation that works and one that does not still differ. This keeps
# that difference from being used to test a list of addresses: every attempt
# counts, a refused one included, per administrator and per process.
ISSUE_ATTEMPTS = 20
ISSUE_WINDOW_SECONDS = 600.0
TOO_MANY_INVITATIONS = ("You have made many invitations in a short time. Wait a few minutes, "
                        "then try again.")
_ISSUE_LIMIT = None


def _limit_scoped_issuance(issuer: str) -> None:
    global _ISSUE_LIMIT
    from maverick.public_rights_form import SlidingWindowLimit

    if _ISSUE_LIMIT is None:
        _ISSUE_LIMIT = SlidingWindowLimit(ISSUE_WINDOW_SECONDS)
    if not _ISSUE_LIMIT.hit(f"workspace-invite:{issuer or 'unknown'}", ISSUE_ATTEMPTS, time.time()):
        raise InviteRateLimited(TOO_MANY_INVITATIONS)


def reset_issue_limit() -> None:
    """Tests only."""
    if _ISSUE_LIMIT is not None:
        _ISSUE_LIMIT.reset()


def existing_local_account(email: str) -> bool:
    """Whether accepting a local invitation for ``email`` would take over an
    existing identity: any identity source that already knows ``user:<email>``.

    Accepting a local invitation sets a passphrase and signs in as
    ``user:<email>``, so whoever holds the link would become that person. The
    sources are the colleague passphrase (or one being reset), the installation
    owner, a configured bootstrap admin, a stored role, any workspace
    membership, an explicit department grant, and the SCIM roster: a user the
    IdP has bound to this principal (active, deactivated or retired) or a role
    that its groups confer. A workspace invitation writes no installation role,
    so a role a SCIM group confers would otherwise pass straight to the invited
    session.

    The SCIM binding is the same strict one that grants access (the IdP's
    ``externalId`` or the record id); a user known only by name or email carries
    no access and is invited as usual. Unreadable state counts as existing
    (fail closed). It is checked when the invitation is made and again when it
    is redeemed.
    """
    from maverick.suite_grants import get_grant, is_admin_principal

    from . import local_passphrases, passphrase_resets, rbac, scim_groups

    email = (email or "").strip().lower()
    principal = "user:" + email
    try:
        return bool(local_passphrases.has_account(email) or local_passphrases.owner_of(email)
                    or passphrase_resets.pending_for(email)
                    or is_admin_principal(principal)
                    or rbac.get_stored_role(principal) is not None
                    or rbac.has_tenant_membership(principal)
                    or get_grant(principal) is not None
                    or scim_groups.active_for_principal(principal) is not None
                    # A group-derived role counts even without a local account.
                    # The resolver fails closed on unreadable policy.
                    or scim_groups.role_for_principal(principal) is not None)
    except Exception:
        return True


def store_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "dashboard-invites.json"


def _locked(path: Path):
    from contextlib import ExitStack

    from maverick.file_lock import cross_process_lock, ensure_private_directory
    from maverick.paths import maverick_home

    ensure_private_directory(maverick_home())
    ensure_private_directory(path.parent)
    with ExitStack() as stack:
        stack.enter_context(_INVITES_LOCK)
        stack.enter_context(cross_process_lock(path))
        return stack.pop_all()


# ---- feature gate ------------------------------------------------------------

def invites_enabled() -> bool:
    """Opt-in, off by default: ``MAVERICK_DASHBOARD_INVITES=1`` or
    ``[dashboard] invites = true``. Off → every invite route 404s and the
    local-session path never runs."""
    from maverick.config import env_flag
    v = env_flag("MAVERICK_DASHBOARD_INVITES")
    if v is None:
        v = env_flag("LIGHTWORK_DASHBOARD_INVITES")
    if v is not None:
        return v
    try:
        from maverick.config import load_config
        dashboard = (load_config() or {}).get("dashboard") or {}
        if "invites" in dashboard:
            return dashboard["invites"] is True
        from .local_owner import claimed
        return claimed()
    except Exception:  # pragma: no cover - config read never gates auth
        return False


# ---- invite lifecycle ----------------------------------------------------------

@dataclass(frozen=True)
class Invite:
    id: str
    email: str
    role: str
    created_by: str
    created_at: float
    expires_at: float
    used_at: float | None = None
    used_by: str | None = None
    tenant: str = ""  # set: the role applies inside this workspace only
    workspace_admin_invite: bool = False  # recheck the issuing member's authority on acceptance
    grant_confirmed_at: float | None = None  # written only after the native role save returns

    @property
    def pending(self) -> bool:
        return self.used_at is None and time.time() < self.expires_at


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _load() -> dict[str, dict]:
    from maverick.file_lock import (
        atomic_read_text,
        ensure_private_directory,
        ensure_private_file,
    )
    from maverick.paths import maverick_home

    p = store_path()
    ensure_private_directory(maverick_home())
    ensure_private_directory(p.parent)
    if not p.exists():
        return {}
    try:
        ensure_private_file(p)
        data = _decode_json(atomic_read_text(p))
    except InviteStoreError:
        raise
    except (OSError, ValueError) as exc:
        raise InviteStoreError(f"invite store unreadable or corrupt: {exc}") from exc
    if not isinstance(data, dict):
        raise InviteStoreError("invite store corrupt: top-level value must be an object")
    out: dict[str, dict] = {}
    for invite_id, rec in data.items():
        out[invite_id] = _validate_record(invite_id, rec)
    return out


def _decode_json(raw: str) -> object:
    def _reject_constant(value: str):
        raise ValueError(f"non-finite number {value!r}")

    def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate key {key!r}")
            out[key] = value
        return out

    try:
        return json.loads(raw, parse_constant=_reject_constant, object_pairs_hook=_object)
    except (TypeError, ValueError) as exc:
        raise InviteStoreError(f"invite store corrupt: {exc}") from exc


def _validate_record(invite_id: str, rec: object) -> dict:
    if not invite_id or invite_id != invite_id.strip() or len(invite_id) > 128:
        raise InviteStoreError("invite store corrupt: invalid invite id")
    if not isinstance(rec, dict) or rec.get("id") != invite_id:
        raise InviteStoreError(f"invite store corrupt: record id mismatch for {invite_id!r}")
    email = rec.get("email")
    role = rec.get("role")
    token_hash = rec.get("token_sha256")
    if (
        not isinstance(email, str)
        or not email
        or len(email) > 320
        or email != email.strip().lower()
        or "@" not in email
    ):
        raise InviteStoreError(f"invite store corrupt: invalid email for {invite_id!r}")
    # Historical invitation material outlives mutable custom role definitions.
    # Current role authority is checked under reservation when redeeming.
    if not isinstance(role, str) or re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", role) is None:
        raise InviteStoreError(f"invite store corrupt: invalid role for {invite_id!r}")
    if (
        not isinstance(token_hash, str)
        or len(token_hash) != 64
        or any(ch not in string.hexdigits for ch in token_hash)
    ):
        raise InviteStoreError(f"invite store corrupt: invalid token digest for {invite_id!r}")
    try:
        created = float(rec["created_at"])
        expires = float(rec["expires_at"])
    except (KeyError, OverflowError, TypeError, ValueError) as exc:
        raise InviteStoreError(f"invite store corrupt: invalid times for {invite_id!r}") from exc
    if not math.isfinite(created) or created < 0 or not math.isfinite(expires) or expires < 0:
        raise InviteStoreError(f"invite store corrupt: non-finite times for {invite_id!r}")
    used_at = rec.get("used_at")
    if used_at is not None:
        try:
            used_at = float(used_at)
        except (OverflowError, TypeError, ValueError) as exc:
            raise InviteStoreError(f"invite store corrupt: invalid used_at for {invite_id!r}") from exc
        if not math.isfinite(used_at) or used_at < 0:
            raise InviteStoreError(f"invite store corrupt: invalid used_at for {invite_id!r}")
    created_by = rec.get("created_by", "")
    used_by = rec.get("used_by")
    if not isinstance(created_by, str) or len(created_by) > 512:
        raise InviteStoreError(f"invite store corrupt: invalid created_by for {invite_id!r}")
    if used_by is not None and (not isinstance(used_by, str) or len(used_by) > 512):
        raise InviteStoreError(f"invite store corrupt: invalid used_by for {invite_id!r}")
    tenant = rec.get("tenant", "")
    if not isinstance(tenant, str) or len(tenant) > 128 or tenant != tenant.strip():
        raise InviteStoreError(f"invite store corrupt: invalid workspace for {invite_id!r}")
    workspace_admin_invite = rec.get("workspace_admin_invite", False)
    if not isinstance(workspace_admin_invite, bool) or (workspace_admin_invite and not tenant):
        raise InviteStoreError(f"invite store corrupt: invalid workspace issuer for {invite_id!r}")
    confirmed = rec.get("grant_confirmed_at")
    if confirmed is not None and (
        isinstance(confirmed, bool) or not isinstance(confirmed, (int, float))
        or not math.isfinite(confirmed) or used_at is None or not used_by or confirmed < used_at
    ):
        raise InviteStoreError(f"invite store corrupt: invalid grant confirmation for {invite_id!r}")
    clean = dict(rec)
    clean["created_at"] = created
    clean["expires_at"] = expires
    clean["used_at"] = used_at
    return clean


def _write(data: dict[str, dict], *, before_effect: Callable[[], None] | None = None) -> None:
    from maverick.file_lock import atomic_write_text
    options = {"effect_guard": before_effect} if before_effect is not None else {}
    atomic_write_text(store_path(), json.dumps(data, indent=2, sort_keys=True), **options)


def expiry_hours(choice: str) -> int:
    """The ordinary invitation form's bounded choices; legacy lifetimes remain unchanged."""
    if choice not in INVITE_EXPIRIES:
        raise ValueError("Choose an invitation expiry from the list.")
    return INVITE_EXPIRIES[choice]


def _to_invite(rec: dict) -> Invite:
    return Invite(id=rec["id"], email=rec["email"], role=rec["role"],
                  created_by=rec.get("created_by", ""),
                  created_at=float(rec.get("created_at", 0)),
                  expires_at=float(rec.get("expires_at", 0)),
                  used_at=rec.get("used_at"), used_by=rec.get("used_by"),
                  tenant=rec.get("tenant", ""),
                  workspace_admin_invite=rec.get("workspace_admin_invite", False),
                  grant_confirmed_at=rec.get("grant_confirmed_at"))


def create_invite(email: str, role: str, *, created_by: str,
                  ttl_hours: float = INVITE_TTL_HOURS, tenant: str = "",
                  workspace_admin_invite: bool = False,
                  before_effect: Callable[[], None] | None = None) -> tuple[Invite, str]:
    """Mint an invite; returns ``(invite, token)``. The token is shown ONCE —
    only its sha256 is stored, so a copied store file yields no working links.
    With ``tenant`` the role is granted inside that workspace only (a
    workspace membership), never as the dashboard-wide role."""
    from . import rbac
    email = (email or "").strip().lower()
    # The stored-record check refuses addresses over 320 characters, so one
    # longer than that written here would make the whole store unreadable.
    if not email or len(email) > 320 or "@" not in email or any(c.isspace() for c in email):
        raise ValueError("a valid email address is required")
    if not rbac.is_known_role(role):
        raise ValueError("unknown role")
    try:
        ttl = float(ttl_hours)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("invite TTL must be a finite number") from exc
    if not math.isfinite(ttl):
        raise ValueError("invite TTL must be a finite number")
    tenant = (tenant or "").strip()
    if len(tenant) > 128 or (workspace_admin_invite and not tenant):
        raise ValueError("invalid workspace")
    if workspace_admin_invite:
        _limit_scoped_issuance(created_by)
    if local_login_mode() and existing_local_account(email):
        from .local_passphrases import ACCOUNT_EXISTS

        raise ExistingAccountError(ACCOUNT_EXISTS)
    token = "inv_" + secrets.token_urlsafe(32)
    inv_id = "invite_" + secrets.token_hex(8)
    now = time.time()
    rec = {"id": inv_id, "email": email, "role": role, "created_by": created_by,
           "created_at": now, "expires_at": now + ttl * 3600,
           "token_sha256": _hash(token), "used_at": None, "used_by": None}
    if tenant:
        rec["tenant"] = tenant
    if workspace_admin_invite:
        rec["workspace_admin_invite"] = True
    with _locked(store_path()):
        data = _load()
        pending = sum(1 for r in data.values()
                      if not r.get("used_at") and r.get("expires_at", 0) > now)
        if pending >= _MAX_PENDING:
            raise ValueError("too many pending invites — revoke some first")
        data[inv_id] = rec
        if before_effect is None:
            _write(data)
        else:
            def guard() -> None:
                before_effect()
                if not rbac.is_known_role(role):
                    raise ValueError("The invitation role changed. Choose its current role again.")
            _write(data, before_effect=guard)
    return _to_invite(rec), token


def list_invites() -> list[Invite]:
    """All stored invites, newest first (used/expired included for the audit
    trail; the UI filters)."""
    return sorted((_to_invite(r) for r in _load().values()),
                  key=lambda i: i.created_at, reverse=True)


def revoke_invite(invite_id: str) -> bool:
    with _locked(store_path()):
        data = _load()
        if data.pop((invite_id or "").strip(), None) is None:
            return False
        _write(data)
        return True


def peek_invite(token: str) -> Invite | None:
    """The pending invite for ``token``, WITHOUT consuming it (the GET
    confirmation page — inert for link scanners). None when unknown/used/expired."""
    inv = lookup_invite(token)
    return inv if inv is not None and inv.pending else None


def lookup_invite(token: str) -> Invite | None:
    """Read the original record, including used links; callers must authorize receipts."""
    if not isinstance(token, str) or not token.startswith("inv_") or len(token) > 128:
        return None
    h = _hash(token)
    for rec in _load().values():
        if secrets.compare_digest(rec.get("token_sha256", ""), h):
            return _to_invite(rec)
    return None


def confirm_grant(invite_id: str, principal: str) -> Invite:
    """Record a completed native grant, never infer one from the current roster."""
    with _locked(store_path()):
        data = _load()
        rec = data.get(invite_id)
        if rec is None or rec.get("used_at") is None or rec.get("used_by") != principal:
            raise InviteStoreError("original invitation redemption changed")
        if rec.get("grant_confirmed_at") is None:
            rec["grant_confirmed_at"] = max(time.time(), rec["used_at"])
            _write(data)
        return _to_invite(rec)


def consume_invite(token: str, *, used_by: str | None = None,
                   before_commit=None) -> Invite | None:
    """Atomically redeem ``token``: marks it used and returns the invite, or
    None when unknown, expired, or already used (single-use is enforced under
    the store lock, so two racing accepts can't both win). ``used_by`` defaults
    to the invited email's own principal (the local-login case).

    ``before_commit(invite)`` runs under the same lock just before the link is
    marked used (it saves the colleague's passphrase). If it raises, the link
    stays unused and the error propagates."""
    from maverick.authority_effects import authority_effect_fence

    from .rbac import is_known_role

    h = _hash(token or "")
    with authority_effect_fence(), _locked(store_path()):
        data = _load()
        for rec in data.values():
            if secrets.compare_digest(rec.get("token_sha256", ""), h):
                inv = _to_invite(rec)
                if not inv.pending or not is_known_role(inv.role):
                    return None
                if before_commit is not None:
                    before_commit(inv)
                rec["used_at"] = time.time()
                rec["used_by"] = used_by or f"user:{inv.email}"
                _write(data)
                return _to_invite(rec)
    return None


# ---- emailing the link ---------------------------------------------------------

def invite_email_enabled() -> bool:
    """Whether minting an invite should also email the link (default ON when a
    sending account is configured; ``[dashboard] invite_email = false`` opts
    out and returns the UI to copy-the-link-yourself)."""
    try:
        from maverick.config import load_config
        v = ((load_config() or {}).get("dashboard") or {}).get("invite_email")
        if v is not None:
            return bool(v)
    except Exception:  # pragma: no cover - config read never gates sending
        pass
    return True


def send_invite_email(invite: Invite, link: str, *, invited_by: str) -> tuple[bool, str]:
    """Best-effort: email the invite link to the invitee. Returns
    ``(sent, reason)`` and NEVER raises — the minting flow stays fail-soft (the
    admin always still gets the copyable link). ``reason`` is a short operator
    hint when not sent ("no sending account configured", an SMTP error, …)."""
    from maverick import mailer
    if not invite_email_enabled():
        return False, "invite emails disabled ([dashboard] invite_email = false)"
    if not mailer.configured():
        return False, "no sending account configured ([email] / EMAIL_USER)"
    days = max(1, int((invite.expires_at - invite.created_at) / 86400))
    destination = f"the {invite.tenant} workspace" if invite.tenant else "a Lightwork dashboard"
    body = (
        f"You've been invited to {destination} as {invite.role} "
        f"(invited by {invited_by}).\n\n"
        f"Open this link to accept:\n\n    {link}\n\n"
        f"The link works once and expires in {days} day{'s' if days != 1 else ''}. "
        f"If you weren't expecting this invitation, ignore this email.\n"
    )
    try:
        mailer.send(invite.email, "You're invited to Lightwork", body)
    except mailer.MailerError as e:
        return False, str(e)
    return True, "sent"


# ---- local (no-IdP) sessions ---------------------------------------------------

def _session_secret_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "dashboard-session.key"


def local_session_secret() -> str:
    """The HMAC key for locally-minted ``mvk_session`` cookies.

    ``MAVERICK_DASHBOARD_SESSION_SECRET`` / ``[dashboard] session_secret`` when
    the operator manages it; otherwise generated once to
    ``~/.maverick/dashboard-session.key`` (0600) — the zero-config path the
    no-IdP customer needs. Distinct from the OIDC ``[auth.oidc] session_secret``
    so enabling SSO later can't silently re-validate old local sessions."""
    import os
    env = os.environ.get("MAVERICK_DASHBOARD_SESSION_SECRET", "").strip()
    if env:
        return env
    try:
        from maverick.config import load_config
        cfg = str(((load_config() or {}).get("dashboard") or {})
                  .get("session_secret") or "").strip()
        if cfg:
            return cfg
    except Exception:  # pragma: no cover - config read never gates auth
        pass
    path = _session_secret_path()
    with _locked(path):
        if path.exists():
            from maverick.file_lock import atomic_read_text, ensure_private_file

            ensure_private_file(path)
            secret = atomic_read_text(path).strip()
            if secret:
                return secret
        secret = secrets.token_urlsafe(48)
        # Create with a private mode and atomically publish it. A plain
        # write_text()+chmod left a local-read window before the chmod and
        # could expose the HMAC key used to mint dashboard sessions.
        from maverick.file_lock import atomic_write_text

        atomic_write_text(path, secret, mode=0o600)
        return secret


def local_login_mode() -> bool:
    """True when invite acceptance must itself sign the browser in: invites are
    on and no OIDC or SAML browser login is configured (with SSO, the IdP signs
    in and the invite only binds the role)."""
    if not invites_enabled():
        return False
    try:
        from maverick.oidc import login_enabled

        from .saml import saml_enabled

        return not login_enabled() and not saml_enabled()
    except Exception:  # pragma: no cover - an unavailable SSO config cannot enable local login
        return False


def session_ttl_seconds() -> int:
    try:
        from maverick.config import load_config
        days = ((load_config() or {}).get("dashboard") or {}).get("invite_session_days")
        if days is not None:
            return max(1, int(float(days) * 86400))
    except Exception:  # pragma: no cover
        pass
    return LOCAL_SESSION_DAYS * 86400


def mint_local_session(email: str, request=None, *, mfa: bool = False, mfa_at: float | None = None) -> str:
    """A signed session cookie value for ``user:<email>`` (no-IdP mode).

    With ``request`` the session is recorded for the Sessions page (a ``sid``
    in the cookie). A passphrase is one factor, so by default there is no second
    factor; ``mfa``/``mfa_at`` are given only when the session carries one that
    was already proved (a renewal keeps it). Without ``request`` -- tests and
    older callers -- it is an untracked legacy cookie."""
    from maverick.oidc import validate_subject
    from maverick.web_session import sign_session

    email = validate_subject(email)
    if request is not None:
        from .oidc_login import mint_browser_session

        return mint_browser_session(request, sub=email, secret=local_session_secret(),
                                    via="invite", mfa=mfa, ttl=session_ttl_seconds(), mfa_at=mfa_at)
    now = int(time.time())
    return sign_session({"sub": email, "iat": now, "exp": now + session_ttl_seconds()},
                        local_session_secret())


def local_session_principal(request):
    """The :class:`~maverick.oidc.VerifiedPrincipal` for a locally-minted
    ``mvk_session`` cookie, or None. Only active in local-login mode, so it can
    never shadow the OIDC session path; revocation epochs apply exactly as they
    do for SSO sessions ("log out everywhere" / deprovision)."""
    if not local_login_mode():
        return None
    raw = request.cookies.get("mvk_session")
    if not raw:
        return None
    from maverick.web_session import verify_session
    payload = verify_session(raw, local_session_secret())
    if not payload:
        return None
    from maverick.oidc import validate_subject
    try:
        sub = validate_subject(payload.get("sub"))
    except ValueError:
        return None
    from .session_revocation import is_revoked
    if is_revoked(sub, payload.get("iat")):
        return None
    from maverick.oidc import VerifiedPrincipal

    from .oidc_login import session_claims
    claims = session_claims(payload, request, via="invite")
    if claims is None:
        return None
    return VerifiedPrincipal(sub=sub, issuer="invite-session", audience="", claims=claims)
