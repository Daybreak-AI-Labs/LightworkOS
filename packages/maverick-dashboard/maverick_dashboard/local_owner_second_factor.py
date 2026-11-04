"""The owner's authenticator app: set-up, the second sign-in step, turning it off,
and recovery codes for a lost phone.

The state lives in the owner record (:mod:`local_owner`) under the same lock as
the passphrase and its failure count:

* ``totp``: the authenticator secret, sealed with the deployment at-rest key;
  ``totp_step``: the last time step that opened a sign-in, so one code cannot
  open two;
* ``totp_setup``: a secret shown during set-up, sealed, until it is confirmed;
* ``recovery``: unused recovery codes, each a salted scrypt digest;
* ``second_factor``: second-step tokens, kept as digests with their purpose,
  expiry and wrong-code count;
* ``flow_proofs``: recovery proofs, one live proof per restricted flow (see
  :func:`recovery_step`), kept as digests with their flow and expiry.

Rules:

* Sign-in asks for a code whenever the owner is enrolled, in every mode. The
  mode (``[auth.local_owner] totp``) only decides whether a owner who has not
  enrolled must set one up, whether set-up is offered, and whether it may be
  turned off.
* A correct passphrase does not clear the failure count while a code is due.
* Every wrong code counts toward the same lock as a wrong passphrase. A
  second-step token takes at most ``ATTEMPTS`` codes, then is discarded.
* A recovery code works once. An authenticator code's time step is remembered.
* A restricted recovery step (company sign-in, company SAML) needs the passphrase
  and a code the first time. The code issues a recovery proof for that flow only:
  a random token, valid ten minutes, stored as a digest, sent as an HttpOnly
  SameSite=Strict cookie on the flow's own path. Later steps of the same flow
  accept the proof instead of a code. The proof is spent when the flow completes
  or is cancelled from the browser that holds it.
* Enabling, turning off, making new recovery codes and using a recovery code are
  recorded in the activity log first. If the log refuses, nothing changes. Ending
  a recovery proof is recorded too, but a refused record does not stop it.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass

from fastapi import HTTPException
from maverick import config, file_lock

from . import owner_totp

log = logging.getLogger(__name__)

PENDING_SECONDS = 300  # the second step, counted from the passphrase
SETUP_SECONDS = 900  # a set-up secret that has not been confirmed yet
PENDING_LIMIT = 5  # second-step tokens kept at once
ATTEMPTS = 5  # wrong codes one second-step token takes
COOKIE = "mvk_owner_second_factor"
COOKIE_PATH = "/auth/owner-second-factor"
PROOF_SECONDS = 600  # a recovery proof: later steps of one restricted flow, for ten minutes
PROOF_COOKIE = "mvk_owner_recovery_proof"
# The restricted flows that take a passphrase and a code. Each proof cookie is
# sent only under its flow's own path, so no other flow receives it.
FLOW_PATHS = {
    "company-signin-activation": "/api/v1/settings/sign-in-migration",
    "company-signin-recovery": "/auth/company-signin-recovery",
    "company-saml-activation": "/api/v1/settings/single-sign-on",
    "company-saml-recovery": "/auth/company-saml-recovery",
}
RESET_KEYS = ("totp", "totp_step", "totp_setup", "recovery", "second_factor", "flow_proofs")
WRONG_CODE = ("That code was not accepted. Check the six-digit code in your authenticator app, "
              "or use one of your recovery codes.")
EXPIRED = "That sign-in step has expired. Sign in with your passphrase again."
SETUP_EXPIRED = "Start the set-up again. Its code has expired."
LOCKED = "Wait one minute before trying again."
REQUIRED = "This installation requires an authenticator app, so it cannot be turned off."
OFF = "This installation does not offer changes to the owner's authenticator app."
ALREADY_ON = "Your authenticator app is already on."
CODE_REQUIRED = ("Enter a current code from your authenticator app, or one of your recovery codes, "
                 "to continue this step.")
NOT_ON = "No authenticator app is set up."
SEALING = "An authenticator app needs encryption at rest, which is unavailable right now."


@dataclass(frozen=True)
class Challenge:
    """Returned instead of a session when a second factor is due.

    ``token`` goes to the browser in a short-lived cookie; the record keeps only
    its digest. ``secret`` and ``uri`` are set only for set-up (``enroll``).
    """

    token: str
    purpose: str
    secret: str = ""
    uri: str = ""


@dataclass(frozen=True)
class Finished:
    """A completed second step: the session, and recovery codes when set-up finished."""

    session: str
    recovery_codes: tuple[str, ...] = ()


def mode() -> str:
    return config.get_auth_local_owner_totp()


def _now() -> float:
    return time.time()


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _strip(code: object) -> str:
    return "".join(str(code or "").split())


def _seal(text: str) -> str:
    from maverick.crypto_at_rest import EncryptionUnavailable, deployment_key_scope, seal_to_str

    try:
        with deployment_key_scope():
            return seal_to_str(text)
    except EncryptionUnavailable as exc:
        raise HTTPException(503, SEALING) from exc


def _secret_key(sealed: object) -> bytes | None:
    """The raw authenticator key behind a sealed value, or None when it cannot be read."""
    from maverick.crypto_at_rest import deployment_key_scope, is_sealed_str, unseal_from_str

    if not is_sealed_str(sealed):
        log.warning("The owner's authenticator secret is not sealed and was not used.")
        return None
    try:
        with deployment_key_scope():
            return owner_totp.decode_secret(unseal_from_str(sealed))
    except Exception:  # noqa: BLE001 - the cause is logged by class name only, never the value
        log.warning("The owner's authenticator secret could not be opened; recovery codes still work.")
        return None


def _issue(row: dict, purpose: str, *, now: float) -> str:
    """A new second-step token for ``row``. Only its digest is stored."""
    token = secrets.token_urlsafe(32)
    live = {d: e for d, e in row.get("second_factor", {}).items() if e["expires"] > now}
    live[_digest(token)] = {"purpose": purpose, "expires": now + PENDING_SECONDS, "attempts": 0}
    newest = sorted(live.items(), key=lambda item: item[1]["expires"])[-PENDING_LIMIT:]
    row["second_factor"] = dict(newest)
    return token


def _live_entry(row: dict, token: object, *, now: float) -> tuple[str, dict]:
    digest = _digest(token) if isinstance(token, str) and token else ""
    entry = row.get("second_factor", {}).get(digest) if digest else None
    if entry is None or entry["expires"] <= now:
        raise HTTPException(401, EXPIRED)
    return digest, entry


def _unlocked(row: dict, *, now: float) -> None:
    if row["locked_until"] > now:
        raise HTTPException(429, LOCKED)


def _audit(verb: str, email: str, detail: str = "owner authenticator app", *, actor: str = "") -> None:
    """Record the change first. An explicit refusal by the activity log stops it."""
    from maverick.audit import AuditRefused, EventKind, audit_event

    actor = actor or "user:" + email
    try:
        audit_event(EventKind.CONTROL_PLANE_ACTION, agent="dashboard", _global=True,
                    verb=verb, principal=actor, actor=actor, ok=True, detail=detail)
    except AuditRefused as exc:
        raise HTTPException(
            503, "The activity log refused to record this change, so nothing was changed. "
                 "Tell an administrator.") from exc


def _setup_key(row: dict, *, now: float) -> bytes:
    setup = row.get("totp_setup")
    if not isinstance(setup, dict) or now - setup["created"] > SETUP_SECONDS:
        raise HTTPException(409, SETUP_EXPIRED)
    key = _secret_key(setup["secret"])
    if key is None:
        raise HTTPException(503, "The set-up code could not be read. Start the set-up again.")
    return key


def _accept(row: dict, code: object, *, now: float) -> str | None:
    """Spend an authenticator code or a recovery code from ``row``.

    Returns ``"app"``, ``"recovery"`` or None. ``row`` changes only on acceptance.
    """
    if "totp" in row:
        key = _secret_key(row["totp"])
        if key is not None:
            step = owner_totp.verify(key, _strip(code), now=now, last_step=int(row.get("totp_step", 0)))
            if step is not None:
                row["totp_step"] = step
                return "app"
    index = owner_totp.recovery_index(row.get("recovery", []), code)
    if index is not None:
        del row["recovery"][index]
        return "recovery"
    return None


def _spend(row: dict, code: object, *, now: float) -> str | None:
    how = _accept(row, code, now=now)
    if how == "recovery":
        _audit("owner_recovery_code_used", row["email"])
    return how


def _passphrase_matches(row: dict, email: object, password: object) -> None:
    from . import local_owner

    email, password = local_owner._credentials(email, password)
    match = hmac.compare_digest(local_owner._password(password, row["salt"]), row["password_hash"])
    if not match or email != row["email"]:
        local_owner._count_failure(row)
        raise HTTPException(401, "The email or passphrase was not accepted.")


def _commit_enrollment(row: dict) -> list[str]:
    """Make the set-up secret the owner's authenticator and issue recovery codes."""
    codes = owner_totp.new_recovery_codes()
    row["totp"] = row["totp_setup"]["secret"]
    del row["totp_setup"]
    row["recovery"] = [owner_totp.new_recovery_entry(code) for code in codes]
    return codes


def _row_or_refuse(*, ready: bool) -> dict:
    from . import local_owner

    row = local_owner._read()
    if row is None or (ready and row["status"] != "ready"):
        raise HTTPException(409, "Complete this computer's owner setup before using the authenticator app.")
    return row


def after_passphrase(row: dict) -> Challenge | None:
    """Called under the owner lock once the passphrase is right. None means sign in now."""
    now = _now()
    if "totp" in row:
        return Challenge(token=_issue(row, "sign_in", now=now), purpose="sign_in")
    if mode() != "required":
        return None
    text = owner_totp.encode_secret(owner_totp.new_secret())
    row["totp_setup"] = {"secret": _seal(text), "created": now}
    return Challenge(token=_issue(row, "enroll", now=now), purpose="enroll", secret=text,
                     uri=owner_totp.otpauth_uri(text, row["email"]))


def _end_unused_session(session: str) -> None:
    """End a session minted for a change that was then refused. Its cookie was never sent."""
    from maverick.web_session import verify_session

    from . import invites, session_registry

    payload = verify_session(session, invites.local_session_secret()) or {}
    if isinstance(payload.get("sid"), str) and payload["sid"]:
        session_registry.revoke(payload["sid"], by="not-completed")


def complete(request, *, token: object, code: object) -> Finished:
    """The second sign-in step: an authenticator code (or set-up code) or a recovery code."""
    from maverick.oidc import VerifiedPrincipal

    from . import local_owner
    from .auth import _enforce_scim_active

    now = _now()
    # The managed sign-in policy and the deprovisioning check apply to this step too:
    # a token begun before either changed does not finish a sign-in.
    local_owner._policy()
    with local_owner._LOCK, file_lock.cross_process_lock(local_owner.path(), strict=True):
        row = _row_or_refuse(ready=False)
        _unlocked(row, now=now)
        _enforce_scim_active(VerifiedPrincipal(sub=row["email"], issuer="invite-session", audience="", claims={}))
        digest, entry = _live_entry(row, token, now=now)
        enrolling = entry["purpose"] == "enroll"
        if enrolling:
            step = owner_totp.verify(_setup_key(row, now=now), _strip(code), now=now)
            how = "app" if step is not None else None
            if how is not None:
                row["totp_step"] = step
        else:
            how = _spend(row, code, now=now)
        if how is None:
            entry["attempts"] += 1
            if entry["attempts"] >= ATTEMPTS:
                del row["second_factor"][digest]
            local_owner._count_failure(row)
            raise HTTPException(401, WRONG_CODE)
        del row["second_factor"][digest]
        row.update(failures=0, locked_until=0)
        codes: list[str] = []
        if enrolling:
            codes = _commit_enrollment(row)
        # The session is made before anything is written: a set-up that cannot
        # finish stores no secret and no codes, and the same code can be tried again.
        session = local_owner._finish(row, request, mfa_at=now)
        if enrolling:
            try:
                _audit("owner_authenticator_enabled", row["email"])
            except HTTPException:
                _end_unused_session(session)
                raise
        local_owner._write(row)
        return Finished(session=session, recovery_codes=tuple(codes))


def challenge_for(token: object) -> Challenge | None:
    """The page data for a live second-step token. No attempt is counted."""
    from . import local_owner

    now = _now()
    row = local_owner._read()
    if row is None:
        return None
    try:
        _, entry = _live_entry(row, token, now=now)
        if entry["purpose"] == "sign_in":
            return Challenge(token=str(token), purpose="sign_in")
        text = owner_totp.encode_secret(_setup_key(row, now=now))
    except HTTPException:
        return None
    return Challenge(token=str(token), purpose="enroll", secret=text,
                     uri=owner_totp.otpauth_uri(text, row["email"]))


def start_setup(password: object) -> tuple[str, str]:
    """The signed-in owner re-enters the passphrase; a new secret is shown for set-up."""
    from . import local_owner

    now = _now()
    with local_owner._LOCK, file_lock.cross_process_lock(local_owner.path(), strict=True):
        row = _row_or_refuse(ready=True)
        _unlocked(row, now=now)
        _passphrase_matches(row, row["email"], password)
        if "totp" in row:
            raise HTTPException(409, ALREADY_ON)
        if mode() == "off":
            raise HTTPException(409, OFF)
        text = owner_totp.encode_secret(owner_totp.new_secret())
        row["totp_setup"] = {"secret": _seal(text), "created": now}
        local_owner._write(row)
        return text, owner_totp.otpauth_uri(text, row["email"])


def pending_setup() -> tuple[str, str] | None:
    """The secret of a set-up that is under way, for showing it again."""
    from . import local_owner

    row = local_owner._read()
    if row is None or "totp_setup" not in row or "totp" in row:
        return None
    try:
        text = owner_totp.encode_secret(_setup_key(row, now=_now()))
    except HTTPException:
        return None
    return text, owner_totp.otpauth_uri(text, row["email"])


def confirm_setup(code: object) -> list[str]:
    """Turn the authenticator app on once a code from it is confirmed."""
    from . import local_owner

    now = _now()
    with local_owner._LOCK, file_lock.cross_process_lock(local_owner.path(), strict=True):
        row = _row_or_refuse(ready=True)
        _unlocked(row, now=now)
        if "totp" in row:
            raise HTTPException(409, ALREADY_ON)
        if mode() == "off":
            raise HTTPException(409, OFF)
        step = owner_totp.verify(_setup_key(row, now=now), _strip(code), now=now)
        if step is None:
            local_owner._count_failure(row)
            raise HTTPException(401, WRONG_CODE)
        row["totp_step"] = step
        _audit("owner_authenticator_enabled", row["email"])
        codes = _commit_enrollment(row)
        row.update(failures=0, locked_until=0)
        local_owner._write(row)
        return codes


def disable(*, password: object, code: object) -> None:
    """Turn the authenticator app off. Needs the passphrase and a current code or a recovery code."""
    from . import local_owner

    now = _now()
    with local_owner._LOCK, file_lock.cross_process_lock(local_owner.path(), strict=True):
        row = _row_or_refuse(ready=True)
        _unlocked(row, now=now)
        if "totp" not in row:
            raise HTTPException(409, NOT_ON)
        if mode() == "required":
            raise HTTPException(409, REQUIRED)
        if mode() == "off":
            raise HTTPException(409, OFF)
        _passphrase_matches(row, row["email"], password)
        if _spend(row, code, now=now) is None:
            local_owner._count_failure(row)
            raise HTTPException(401, WRONG_CODE)
        _audit("owner_authenticator_disabled", row["email"])
        for key in ("totp", "totp_step", "totp_setup", "recovery"):
            row.pop(key, None)
        row.update(failures=0, locked_until=0)
        local_owner._write(row)


def regenerate(*, code: object) -> list[str]:
    """New recovery codes. The old ones stop working. Needs a current code or a recovery code."""
    from . import local_owner

    now = _now()
    with local_owner._LOCK, file_lock.cross_process_lock(local_owner.path(), strict=True):
        row = _row_or_refuse(ready=True)
        _unlocked(row, now=now)
        if "totp" not in row:
            raise HTTPException(409, NOT_ON)
        if mode() == "off":
            raise HTTPException(409, OFF)
        if _spend(row, code, now=now) is None:
            local_owner._count_failure(row)
            raise HTTPException(401, WRONG_CODE)
        _audit("owner_recovery_codes_regenerated", row["email"])
        codes = owner_totp.new_recovery_codes()
        row["recovery"] = [owner_totp.new_recovery_entry(code_text) for code_text in codes]
        row.update(failures=0, locked_until=0)
        local_owner._write(row)
        return codes


def status(row: dict) -> dict:
    return {"mode": mode(), "enrolled": "totp" in row, "unused_recovery": len(row.get("recovery", []))}


def _proof_key(row: dict, flow: str, token: str) -> str:
    """The stored digest of a recovery proof, bound to the owner and to its flow."""
    return hashlib.sha256(f"{flow}\n{row['email']}\n{token}".encode()).hexdigest()


def _issue_proof(row: dict, flow: str, *, now: float) -> str:
    """A new recovery proof for ``flow``, replacing any earlier one for that flow."""
    token = secrets.token_urlsafe(32)
    kept = {k: v for k, v in row.get("flow_proofs", {}).items() if v["expires"] > now and v["flow"] != flow}
    kept[_proof_key(row, flow, token)] = {"flow": flow, "expires": now + PROOF_SECONDS}
    row["flow_proofs"] = kept
    return token


def recovery_step(request, row: dict, *, flow: str, code: object) -> None:
    """The owner's second factor for one restricted step of ``flow``, under the owner lock.

    The passphrase has already been checked. A live proof for this flow passes the
    step with no code. Otherwise a current authenticator code or an unused
    recovery code passes it and issues a new proof for the flow, which
    :func:`attach_proof` hands to the browser. A missing code is refused without
    counting; a wrong one counts toward the owner's lock. ``row`` is written only
    when a code is accepted, and after its audit events are recorded.
    """
    from . import local_owner

    if flow not in FLOW_PATHS:
        raise ValueError("unknown restricted flow")
    now = _now()
    presented = request.cookies.get(PROOF_COOKIE) or ""
    entry = row.get("flow_proofs", {}).get(_proof_key(row, flow, presented)) if presented else None
    if entry is not None and entry["expires"] > now:
        _audit("owner_recovery_proof_used", row["email"], f"recovery flow {flow}")
        return
    how = _accept(row, code, now=now)
    if how is None:
        if not _strip(code):
            raise HTTPException(401, CODE_REQUIRED)
        local_owner._count_failure(row)
        raise HTTPException(401, WRONG_CODE)
    if how == "recovery":
        _audit("owner_recovery_code_used", row["email"])
    _audit("owner_recovery_proof_issued", row["email"], f"recovery flow {flow}")
    row.update(failures=0, locked_until=0)
    token = _issue_proof(row, flow, now=now)
    local_owner._write(row)
    request.state.owner_recovery_proof = (flow, token)


def _proof_cookie(request, response, flow: str, token: str) -> None:
    from .oidc_login import _cookie_secure

    response.set_cookie(PROOF_COOKIE, token, max_age=PROOF_SECONDS, path=FLOW_PATHS[flow],
                        httponly=True, samesite="strict", secure=_cookie_secure(request))


def attach_proof(request, response) -> None:
    """Give the browser the recovery proof this request issued, for its flow's path only."""
    issued = getattr(request.state, "owner_recovery_proof", None)
    if issued is not None:
        _proof_cookie(request, response, *issued)


def proof_headers(request) -> dict[str, str]:
    """The same cookie as :func:`attach_proof`, as a header, for a refusal the app answers."""
    issued = getattr(request.state, "owner_recovery_proof", None)
    if issued is None:
        return {}
    from starlette.responses import Response

    response = Response()
    _proof_cookie(request, response, *issued)
    return {"set-cookie": response.headers["set-cookie"]}


def _record_end(email: str, flow: str) -> None:
    """Record a spent recovery proof. A refused log is logged, not raised: the step is already
    done, and ending a proof only removes authority, so it must not fail the request."""
    try:
        _audit("owner_recovery_proof_ended", email, f"recovery flow {flow}")
    except HTTPException:
        log.warning("The activity log refused to record the end of a recovery flow; the proof was still spent.")


def close_flow(response, *, flow: str, presented: str | None = None) -> None:
    """Spend a restricted flow's recovery proof when the flow completes or is cancelled.

    A completed step spends every proof of its flow (``presented`` is None). A cancel
    spends only the proof its own browser presents (``presented``, possibly empty), so
    a request without that proof changes nothing.
    """
    from . import local_owner

    if flow not in FLOW_PATHS:
        raise ValueError("unknown restricted flow")
    with local_owner._LOCK, file_lock.cross_process_lock(local_owner.path(), strict=True):
        row = local_owner._read()
        proofs = (row or {}).get("flow_proofs") or {}
        if presented is None:
            spent = {k for k, v in proofs.items() if v["flow"] == flow}
        else:
            key = _proof_key(row, flow, presented) if row is not None and presented else ""
            spent = {key} if key in proofs and proofs[key]["flow"] == flow else set()
        if spent:
            kept = {k: v for k, v in proofs.items() if k not in spent}
            if kept:
                row["flow_proofs"] = kept
            else:
                row.pop("flow_proofs", None)
            local_owner._write(row)
            _record_end(row["email"], flow)
    response.delete_cookie(PROOF_COOKIE, path=FLOW_PATHS[flow])


def reset_by_operator(*, confirm_email: str, actor: str) -> bool:
    """Host-only reset for a lost phone whose recovery codes are all used.

    Turns the authenticator app off and deletes its recovery codes, any set-up
    under way, and pending sign-in tokens and recovery proofs. The operator must
    type the owner's email. Returns whether an app was on. Used by
    ``maverick owner reset-authenticator``; no dashboard route reaches it.
    """
    from . import local_owner

    with local_owner._LOCK, file_lock.cross_process_lock(local_owner.path(), strict=True):
        row = local_owner._read()
        if row is None:
            raise LookupError("No local owner has been set up on this computer.")
        if confirm_email.strip().lower() != row["email"]:
            raise ValueError("The email does not match this computer's owner. Nothing was changed.")
        was_on = "totp" in row
        _audit("owner_authenticator_reset", row["email"],
               "owner authenticator app; reset from this computer's command line", actor=actor)
        for key in RESET_KEYS:
            row.pop(key, None)
        local_owner._write(row)
        return was_on
