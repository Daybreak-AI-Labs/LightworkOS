"""One-time local owner enrollment, with existing invite-session authentication.

The private claim closes ambient access before any roster mutation. A failed
claim can be completed only with its original passphrase; login never restores
privileges to a completed owner whose role was subsequently changed.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import os
import secrets
import threading
import time

from fastapi import HTTPException, Request
from maverick import config, file_lock
from maverick.paths import maverick_home

_LOCK = threading.RLock()
_SCHEMA = "lightwork.local-owner.v1"


def path():
    return maverick_home() / "dashboard-owner.json"


def claimed() -> bool:
    # A malformed claim must still turn off anonymous administrator access.
    return path().exists()


def _read():
    try:
        file_lock.ensure_private_file(path())
        if path().stat().st_size > 8192:
            raise ValueError("owner claim exceeds its bound")
        row = json.loads(file_lock.atomic_read_text(path()))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise HTTPException(503, "Local owner authority is unavailable.") from exc
    if (not isinstance(row, dict) or row.get("schema") != _SCHEMA
            or row.get("status") not in {"pending", "ready"}
            or not isinstance(row.get("email"), str) or "@" not in row["email"]
            or len(row["email"]) > 320
            or not isinstance(row.get("salt"), str) or len(row["salt"]) != 32
            or not isinstance(row.get("password_hash"), str) or len(row["password_hash"]) != 64
            or type(row.get("failures")) is not int or not 0 <= row["failures"] <= 5
            or not isinstance(row.get("locked_until"), (int, float))
            or not math.isfinite(row["locked_until"])):
        raise HTTPException(503, "Local owner authority is unavailable.")
    try:
        bytes.fromhex(row["salt"])
        bytes.fromhex(row["password_hash"])
    except ValueError as exc:
        raise HTTPException(503, "Local owner authority is unavailable.") from exc
    if not _second_factor_shape_ok(row):
        raise HTTPException(503, "Local owner authority is unavailable.")
    return row


def _hex_of(value: object, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _second_factor_shape_ok(row: dict) -> bool:
    """The optional authenticator-app keys (see :mod:`local_owner_second_factor`)."""
    from . import local_owner_second_factor as second
    from . import owner_totp
    if "totp" in row and not isinstance(row["totp"], str):
        return False
    if "totp_step" in row and (type(row["totp_step"]) is not int or row["totp_step"] < 0):
        return False
    setup = row.get("totp_setup")
    if setup is not None and (not isinstance(setup, dict) or not isinstance(setup.get("secret"), str)
                              or type(setup.get("created")) not in {int, float}):
        return False
    recovery = row.get("recovery")
    if recovery is not None and (not isinstance(recovery, list)
                                 or len(recovery) > owner_totp.RECOVERY_CODE_COUNT
                                 or not all(isinstance(e, dict) and _hex_of(e.get("salt"), 32)
                                            and _hex_of(e.get("hash"), 64) for e in recovery)):
        return False
    pending = row.get("second_factor")
    if pending is not None and (not isinstance(pending, dict) or len(pending) > 5
                                or not all(_pending_ok(v) for v in pending.values())):
        return False
    proofs = row.get("flow_proofs")
    if proofs is not None and (not isinstance(proofs, dict)
                               or len(proofs) > len(second.FLOW_PATHS)
                               or not all(_hex_of(k, 64) and _proof_ok(v) for k, v in proofs.items())):
        return False
    return True


def _pending_ok(value: object) -> bool:
    return (isinstance(value, dict) and value.get("purpose") in {"sign_in", "enroll"}
            and type(value.get("expires")) in {int, float} and math.isfinite(value["expires"])
            and type(value.get("attempts")) is int and 0 <= value["attempts"] <= 5)


def _proof_ok(value: object) -> bool:
    from . import local_owner_second_factor as second
    return (isinstance(value, dict) and value.get("flow") in second.FLOW_PATHS
            and type(value.get("expires")) in {int, float} and math.isfinite(value["expires"]))


def _write(row):
    file_lock.atomic_write_text(path(), json.dumps(row, sort_keys=True), mode=0o600)


def _count_failure(row) -> None:
    """One wrong passphrase or code: five in a row lock sign-in for a minute."""
    row["failures"] = min(5, row["failures"] + 1)
    row["locked_until"] = time.time() + 60 if row["failures"] == 5 else 0
    _write(row)


def _local(request: Request, *, mutate=False):
    try:
        peer = ipaddress.ip_address(request.client.host)
        host = request.url.hostname
        host_local = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(403, "Open owner setup on this computer's loopback address.") from None
    if (not peer.is_loopback or not host_local
            or any(name in request.headers for name in (
                "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip"))):
        raise HTTPException(403, "Owner setup does not accept remote or forwarded requests.")
    if mutate and request.headers.get("origin") != f"{request.url.scheme}://{request.url.netloc}":
        raise HTTPException(403, "Open this Lightwork page before submitting the form.")


def sign_in_available_for(cfg: dict, *, bootstrap: bool = False) -> bool:
    """Whether this configuration still permits the loopback owner login.

    Explicitly disabled OIDC/SAML details are stageable. Active or malformed
    enterprise identity policy never counts as owner-passphrase recovery.
    """
    auth_table = cfg.get("auth")
    if "auth" in cfg and not isinstance(auth_table, dict):
        return False
    if isinstance(auth_table, dict) and "local_owner" in auth_table:
        # [auth.local_owner] is the owner's own policy, not an identity provider.
        auth_table = {k: v for k, v in auth_table.items() if k != "local_owner"}
    if auth_table:
        if bootstrap or not set(auth_table) <= {"oidc", "saml"}:
            return False
        saml_table = auth_table.get("saml")
        if saml_table is not None and (not isinstance(saml_table, dict) or saml_table.get("enabled") is not False):
            return False
        oidc_table = auth_table.get("oidc", {})
        if not isinstance(oidc_table, dict):
            return False
        enabled = config.env_flag("MAVERICK_OIDC_ENABLED")
        oidc_enabled = enabled if enabled is not None else bool(oidc_table.get("enabled", False))
        if oidc_enabled:
            return False
    dashboard = cfg.get("dashboard") or {}
    if not isinstance(dashboard, dict):
        return False
    proxy_enabled = config.env_flag("MAVERICK_PROXY_AUTH")
    return not (cfg.get("proxy_auth") or proxy_enabled is True
                or any(os.environ.get(name) for name in (
                    "MAVERICK_DASHBOARD_TOKEN", "LIGHTWORK_DASHBOARD_TOKEN"))
                or dashboard.get("token"))


def _policy(*, bootstrap=False):
    from . import auth

    cfg = config.load_global_config()
    if config.config_source_errors() or not isinstance(cfg, dict):
        raise HTTPException(503, "Authentication policy is unavailable.")
    dashboard = cfg.get("dashboard") or {}
    if not isinstance(dashboard, dict):
        raise HTTPException(503, "Authentication policy is unavailable.")
    # Partial enterprise identity configuration also denies local enrollment.
    from ._shared import dashboard_token

    if (not sign_in_available_for(cfg, bootstrap=bootstrap) or dashboard_token()
            or auth.oidc_enabled() or auth.proxy_auth_enabled()
            or auth._saml_policy_configured()):
        raise HTTPException(409, "This installation uses managed sign-in. Use its configured sign-in method.")
    invite_override = config.env_flag("MAVERICK_DASHBOARD_INVITES")
    if invite_override is None:
        invite_override = config.env_flag("LIGHTWORK_DASHBOARD_INVITES")
    if invite_override is False or dashboard.get("invites") is False:
        raise HTTPException(409, "Deployment policy disables local invite sign-in.")
    if bootstrap:
        enabled = config.env_flag("MAVERICK_LOCAL_OWNER_SETUP")
        if enabled is None:
            enabled = config.env_flag("LIGHTWORK_LOCAL_OWNER_SETUP")
        if enabled is False or dashboard.get("local_owner_setup", True) is not True:
            raise HTTPException(409, "Deployment policy disables first-owner setup.")
        if not auth.anonymous_local_access_allowed():
            raise HTTPException(409, "First-owner setup is available only before sign-in is configured.")


def available(request: Request) -> bool:
    try:
        _local(request)
        if claimed():
            return False
        _policy(bootstrap=True)
        from maverick.suite_grants import admin_principals

        from . import invites, rbac
        return not rbac.list_users() and not invites.list_invites() and not admin_principals()
    except Exception:
        return False


def _password(password: str, salt: str) -> str:
    return hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt),
                          n=16384, r=8, p=1, dklen=32).hex()


def _credentials(email, password):
    email = str(email or "").strip().lower()
    if (len(email) > 320 or "@" not in email or any(c.isspace() for c in email)
            or any(ord(c) < 32 for c in email)):
        raise HTTPException(422, "Enter a valid email address for the local owner.")
    if not isinstance(password, str) or not 14 <= len(password) <= 1024:
        raise HTTPException(422, "Use a passphrase between 14 and 1,024 characters.")
    return email, password


def _claim(row) -> None:
    """Complete a pending owner claim: the administrator role, then ``ready``. No session."""
    from . import auth, invites, rbac
    principal = "user:" + row["email"]
    try:
        existing = rbac.list_users()
        if existing and existing != {principal: "admin"}:
            raise HTTPException(409, "Owner setup conflicts with existing role assignments. No roles were changed.")
        rbac.set_role(principal, "admin", actor=principal)
    except rbac.RosterMissingError:
        # A configured administrator is an administrator without a stored
        # role, and can start a new role list from the Users page.
        if not auth.is_dashboard_admin(principal):
            raise
    # Generate the session key before the claim is completed; any failure
    # retains pending ownership rather than silently reopening bootstrap.
    invites.local_session_secret()
    row["status"] = "ready"
    _write(row)


def _finish(row, request=None, *, mfa_at=None):
    """Complete a pending claim and mint the session.

    ``mfa_at`` is given only after the owner's authenticator code (or recovery
    code) was accepted; the session then records a second factor at that time.
    """
    from . import auth, invites, rbac
    principal = "user:" + row["email"]
    if row["status"] == "pending":
        _claim(row)
    elif not auth.is_dashboard_admin(principal) and rbac.get_stored_role(principal) is None:
        # A configured administrator is checked first: they keep access when
        # the role list is lost, and it is how they reach the page that
        # starts a new one.
        raise HTTPException(403, "This local account no longer has an assigned role. Contact a current administrator.")
    if mfa_at is None:
        return invites.mint_local_session(row["email"], request=request)
    from maverick.oidc import validate_subject

    from .oidc_login import mint_browser_session
    return mint_browser_session(request, sub=validate_subject(row["email"]),
                                secret=invites.local_session_secret(), via="invite", mfa=True,
                                ttl=invites.session_ttl_seconds(), mfa_at=mfa_at)


def enroll(request: Request, *, email: str, password: str, confirm: bool):
    _local(request, mutate=True)
    if confirm is not True:
        raise HTTPException(422, "Review and confirm the change to named sign-in.")
    email, password = _credentials(email, password)
    file_lock.ensure_private_directory(maverick_home())
    with _LOCK, file_lock.cross_process_lock(path(), strict=True):
        if claimed():
            raise HTTPException(409, "An owner has already been claimed. Sign in to complete or continue setup.")
        _policy(bootstrap=True)
        from maverick.suite_grants import admin_principals

        from . import invites, rbac
        if rbac.list_users() or invites.list_invites() or admin_principals():
            raise HTTPException(409, "Existing identity assignments prevent first-owner setup.")
        salt = secrets.token_hex(16)
        row = {"schema": _SCHEMA, "email": email, "salt": salt,
               "password_hash": _password(password, salt), "status": "pending",
               "created_at": time.time(), "failures": 0, "locked_until": 0}
        _write(row)
        from . import local_owner_second_factor as second
        if second.mode() == "required":
            # The owner claim is completed, but no session exists until the
            # authenticator app is set up and its code accepted.
            _claim(row)
            challenge = second.after_passphrase(row)
            if challenge is None:  # the policy changed meanwhile: nothing is minted
                raise HTTPException(409, "Owner setup could not finish. Try again.")
            _write(row)
            return challenge
        return _finish(row, request)


def login(request: Request, *, email: str, password: str):
    """A session token, or a second-step challenge when the owner's authenticator
    app must be used first (see :mod:`local_owner_second_factor`)."""
    _local(request, mutate=True)
    _policy()
    email, password = _credentials(email, password)
    with _LOCK, file_lock.cross_process_lock(path(), strict=True):
        row = _read()
        if row is None:
            raise HTTPException(404, "A local owner has not been set up.")
        if row["locked_until"] > time.time():
            raise HTTPException(429, "Wait one minute before trying owner sign-in again.")
        match = hmac.compare_digest(_password(password, row["salt"]), row["password_hash"])
        if not match or email != row["email"]:
            _count_failure(row)
            raise HTTPException(401, "The email or passphrase was not accepted.")
        from maverick.oidc import VerifiedPrincipal

        from .auth import _enforce_scim_active
        _enforce_scim_active(VerifiedPrincipal(sub=email, issuer="invite-session", audience="", claims={}))
        from .local_owner_second_factor import after_passphrase
        # While a second factor is due the failure count is kept: clearing it here
        # would let a passphrase holder reset the lock between code guesses.
        challenge = after_passphrase(row)
        if challenge is not None:
            _write(row)
            return challenge
        row.update(failures=0, locked_until=0)
        _write(row)
        return _finish(row, request)


def verify_recovery(request: Request, *, email: str, password: str, flow: str, code: object = ""):
    """Verify the existing owner for one restricted operation; mint no session.

    An owner with an authenticator app must also give a current code or an unused
    recovery code, or present the recovery proof that this ``flow`` issued to the
    browser earlier (see :mod:`local_owner_second_factor`). The caller must
    enforce its prospective managed policy. This primitive never enrolls an
    owner, completes pending enrollment or restores a role.
    """
    from maverick.authority_effects import authority_effect_fence
    from maverick.oidc import VerifiedPrincipal

    from . import auth, rbac

    _local(request, mutate=True)
    email, password = _credentials(email, password)
    with authority_effect_fence(), _LOCK, file_lock.cross_process_lock(path(), strict=True):
        row = _read()
        if row is None or row["status"] != "ready":
            raise HTTPException(409, "Complete this computer's owner setup before using restricted recovery.")
        if row["locked_until"] > time.time():
            raise HTTPException(429, "Wait one minute before trying the owner passphrase again.")
        match = hmac.compare_digest(_password(password, row["salt"]), row["password_hash"])
        if not match or email != row["email"]:
            row["failures"] = min(5, row["failures"] + 1)
            row["locked_until"] = time.time() + 60 if row["failures"] == 5 else 0
            _write(row)
            raise HTTPException(401, "The email or passphrase was not accepted.")
        role = rbac.get_stored_role("user:" + row["email"])
        if role is None or "admin" not in rbac.permissions_for(role):
            raise HTTPException(403, "The original owner's current role cannot manage installation sign-in.")
        auth._enforce_scim_active(VerifiedPrincipal(sub=email, issuer="invite-session", audience="", claims={}))
        if "totp" in row:
            # The passphrase alone never opens a restricted step for an owner with an app.
            # A code that is accepted is kept by the owner record; a wrong one counts toward the lock.
            from . import local_owner_second_factor as second
            second.recovery_step(request, row, flow=flow, code=code)
        else:
            row.update(failures=0, locked_until=0)
            _write(row)
        return row
