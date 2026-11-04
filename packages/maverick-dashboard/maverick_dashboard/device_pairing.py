"""Short-lived device codes and revocable own-work companion credentials.

Credentials never authorize general dashboard routes. The encrypted installation
registry is deliberately independent of a browser's selected workspace; each
approved record contains the exact tenant and principal that must be rebound.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from contextlib import contextmanager

from fastapi import HTTPException
from maverick import config
from maverick.authority_effects import authority_effect_fence
from maverick.crypto_at_rest import deployment_key_scope, is_sealed, seal, unseal
from maverick.file_lock import atomic_write_bytes, cross_process_lock, ensure_private_directory
from maverick.oidc import VerifiedPrincipal
from maverick.paths import current_tenant_id_strict, maverick_home, reset_tenant, set_tenant

PREFIX = "lwdev1_"
PAIR_PREFIX = "lwpair1_"
PAIR_TTL = 300
ENROLLMENT_TTL = 30 * 86400
READ_PATHS = re.compile(r"^/api/v1/(?:goals(?:/search|/[1-9][0-9]*(?:/events|/open_questions)?)?|oversight/active|spend|glance|goal-tree|offline/bundle)$")


def _policy(*, global_only=False):
    if config.config_source_errors(include_tenant=not global_only):
        raise HTTPException(503, "Device policy is unavailable. Try again after your administrator checks it.")
    sections = [config.load_global_config().get("device_pairing", {})]
    if not global_only:
        sections.append(config.load_config().get("device_pairing", {}))
    ttl = 168 * 3600
    actions = True
    for section in sections:
        if not isinstance(section, dict) or section.get("enabled") is not True:
            raise HTTPException(403, "Device pairing is turned off by your organization.")
        hours = section.get("credential_hours", 24)
        if type(hours) is not int or not 1 <= hours <= 168:
            raise HTTPException(503, "Device credential policy is unavailable.")
        ttl = min(ttl, hours * 3600)
        actions = actions and section.get("allow_actions") is True
    return {"ttl": ttl, "actions": actions}


def _path():
    return maverick_home() / "device-pairing" / "registry.enc"


@contextmanager
def _locked():
    ensure_private_directory(_path().parent)
    with authority_effect_fence(), cross_process_lock(_path(), strict=True), deployment_key_scope():
        yield


def _load():
    try:
        blob = _path().read_bytes()
    except FileNotFoundError:
        return {"version": 1, "pending": {}, "devices": {}}
    if len(blob) > 8 * 1024 * 1024 or not is_sealed(blob):
        raise HTTPException(503, "The device registry could not be verified.")
    try:
        value = json.loads(unseal(blob))
        if (value.get("version") != 1 or not isinstance(value.get("pending"), dict)
                or not isinstance(value.get("devices"), dict)
                or len(value["pending"]) > 1000 or len(value["devices"]) > 2000):
            raise ValueError("registry shape")
        return value
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(503, "The device registry could not be verified.") from exc


def _save(value, *, effect_guard=None):
    now = time.time()
    value["pending"] = {key: row for key, row in value["pending"].items() if row["expires_at"] > now}
    value["devices"] = {key: row for key, row in value["devices"].items() if row.get("work_attempts") or (row["enrollment_expires_at"] > now and not row.get("revoked"))}
    protected = seal(json.dumps(value, separators=(",", ":")).encode())
    if len(protected) > 8 * 1024 * 1024:
        raise HTTPException(409, "The retained device history is full. Nothing was discarded or repeated; use the full dashboard for new work.")
    atomic_write_bytes(_path(), protected, mode=0o600, effect_guard=effect_guard)


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _split(value, prefix):
    pattern = re.escape(prefix) + r"([a-f0-9]{32})\.([A-Za-z0-9_-]{43})"
    match = re.fullmatch(pattern, value or "")
    if not match:
        raise HTTPException(401, "The device credential is unavailable. Pair this device again.")
    return match.groups()


def _audit(actor, action, device):
    from maverick.audit import audit_event
    if audit_event("paired_device_changed", actor=actor, action=action, device_id=device) is not True:
        raise HTTPException(503, "The device change could not be recorded. Nothing was changed.")


def _current(principal, issued_at=None):
    from maverick.personal_identity import principal_current

    from .session_revocation import is_revoked
    tenant = current_tenant_id_strict()
    if tenant:
        from maverick.tenant.registry import is_active
        if not is_active(tenant):
            raise HTTPException(401, "This workspace is no longer available to the device.")
    if not principal_current(principal) or (issued_at is not None and
            (is_revoked(principal[5:], issued_at) or is_revoked(principal, issued_at))):
        raise HTTPException(401, "This account is no longer available to the device. Sign in and pair again.")


def begin(label, peer):
    _policy(global_only=True)
    with _locked():
        state, now = _load(), time.time()
        pending = {key: row for key, row in state["pending"].items() if row["expires_at"] > now}
        peer_hash = _hash(peer)
        if len(pending) >= 1000 or sum(row["peer"] == peer_hash for row in pending.values()) >= 10:
            raise HTTPException(429, "Too many pairing requests. Wait five minutes, then try again.")
        ident, secret = secrets.token_hex(16), secrets.token_urlsafe(32)
        # 60 random bits; neither a short PIN nor a credential. Browser approval
        # still requires a fresh signed-in named principal and same-origin POST.
        code = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(12))
        pending[ident] = {"secret_hash": _hash(secret), "code": code, "label": label,
                          "peer": peer_hash, "created_at": now, "expires_at": now + PAIR_TTL, "status": "pending"}
        state["pending"] = pending
        _save(state)
    return {"pairing_token": PAIR_PREFIX + ident + "." + secret, "code": code, "expires_at": now + PAIR_TTL,
            "scope": "Read only your own tasks, task activity and costs", "interval": 5}


def _pending(state, code):
    if not re.fullmatch(r"[A-Z2-9]{12}", code):
        raise HTTPException(404, "That pairing request is unavailable or expired.")
    row = next((row for row in state["pending"].values() if hmac.compare_digest(row["code"], code)), None)
    if not row or row["expires_at"] <= time.time() or row["status"] != "pending":
        raise HTTPException(404, "That pairing request is unavailable or expired.")
    return row


def review(principal, code):
    policy = _policy()
    _current(principal)
    with _locked():
        row = _pending(_load(), code)
        return {key: row[key] for key in ("code", "label", "created_at", "expires_at")} | {
            "principal": principal, "tenant": current_tenant_id_strict(), "allow_actions": policy["actions"],
            "scope": "Read only your own tasks, activity and costs", "credential_seconds": policy["ttl"]}


def confirm(principal, code, *, actions=False, new_tasks=False, approvals=False):
    if type(new_tasks) is not bool or type(approvals) is not bool:
        raise HTTPException(422, "Choose each additional device permission separately.")
    with _locked():
        policy = _policy()
        _current(principal)
        state, now = _load(), time.time()
        pending = _pending(state, code)
        if (actions or new_tasks or approvals) and not policy["actions"]:
            raise HTTPException(403, "Your organization does not allow companion actions.")
        active = [row for row in state["devices"].values() if not row.get("revoked") and row["enrollment_expires_at"] > now]
        if len(state["devices"]) >= 2000 or sum(row["principal"] == principal for row in active) >= 20:
            raise HTTPException(409, "The paired-device limit was reached. Remove an unused device first.")
        ident, secret = secrets.token_hex(16), secrets.token_urlsafe(32)
        token = PREFIX + ident + "." + secret
        device = {"id": ident, "label": pending["label"], "principal": principal, "tenant": current_tenant_id_strict(),
                  "issued_at": now, "expires_at": now + policy["ttl"], "enrollment_expires_at": now + ENROLLMENT_TTL,
                  "secret_hash": _hash(secret), "generation": 1, "actions": actions,
                  "new_tasks": new_tasks, "approvals": approvals, "revoked": False}
        _audit(principal, "paired", ident)
        state["devices"][ident] = device
        pending.update(status="approved", token=token, device_id=ident, expires_at=min(pending["expires_at"], now + 60))
        _save(state)
        return _public(device)


def poll(token):
    _policy(global_only=True)
    ident, secret = _split(token, PAIR_PREFIX)
    with _locked():
        state = _load()
        row = state["pending"].get(ident)
        if not row or row["expires_at"] <= time.time() or not hmac.compare_digest(row["secret_hash"], _hash(secret)):
            raise HTTPException(401, "Pairing expired. Start a new request on this device.")
        if row["status"] != "approved":
            return {"status": "pending", "expires_at": row["expires_at"]}
        device = state["devices"].get(row["device_id"])
        if not device or device.get("revoked"):
            raise HTTPException(401, "This pairing was removed. Start again.")
        pin = set_tenant(device["tenant"])
        try:
            _policy()
            _current(device["principal"], device["issued_at"])
        finally:
            reset_tenant(pin)
        return {"status": "approved", "token": row["token"], "device": _public(device)}


def _public(row):
    return {key: row[key] for key in ("id", "label", "principal", "tenant", "issued_at", "expires_at", "enrollment_expires_at", "generation", "actions", "revoked")} | {
        "new_tasks": row.get("new_tasks") is True, "approvals": row.get("approvals") is True}


def _scope(method, path, row, policy):
    if method == "GET" and READ_PATHS.fullmatch(path):
        return
    if method == "POST" and path in {"/api/v1/devices/renew", "/api/v1/devices/remove-self"}:
        return
    if method == "GET" and path == "/api/v1/devices/actions/context" and row["actions"] and policy["actions"]:
        return
    if (method == "POST" and path in {"/api/v1/devices/actions/prepare", "/api/v1/devices/actions/execute"}
            and row["actions"] and policy["actions"]):
        return
    if ((method == "GET" and path in {"/api/v1/devices/work/history", "/api/v1/devices/work/original"})
            or (method == "POST" and path == "/api/v1/devices/work/original")):
        return
    if (policy["actions"] and (row.get("new_tasks") is True or row.get("approvals") is True)
            and ((method == "GET" and path in {"/api/v1/devices/work/context", "/api/v1/devices/work/approvals", "/api/v1/devices/work/history", "/api/v1/devices/work/original"})
                 or (method == "POST" and path in {"/api/v1/devices/work/prepare", "/api/v1/devices/work/execute", "/api/v1/devices/work/original"}))):
        return
    raise HTTPException(403, "This paired device cannot perform that operation. Open the signed-in dashboard.")


def authenticate(token, method, path):
    ident, secret = _split(token, PREFIX)
    with _locked():
        row = _load()["devices"].get(ident)
        now = time.time()
        secret_hash = _hash(secret)
        renewal = (row or {}).get("renewal", {})
        recovery = (method == "POST" and path == "/api/v1/devices/renew" and renewal.get("until", 0) > now
                    and hmac.compare_digest(renewal.get("previous_hash", ""), secret_hash))
        if (not row or row.get("revoked") or row["expires_at"] <= now or row["enrollment_expires_at"] <= now
                or not (hmac.compare_digest(row["secret_hash"], secret_hash) or recovery)):
            raise HTTPException(401, "This device connection expired or was removed. Pair it again.")
        # A process/client floor may narrow this deployment; a device cannot
        # cross it even if its registry was restored from another deployment.
        floor = current_tenant_id_strict()
        if floor is not None and floor != row["tenant"]:
            raise HTTPException(403, "This device belongs to a different workspace.")
        pin = set_tenant(row["tenant"])
        try:
            policy = _policy()
            _current(row["principal"], row["issued_at"])
            if row["issued_at"] + policy["ttl"] <= now:
                raise HTTPException(401, "Device credential policy changed. Pair this device again.")
            _scope(method, path, row, policy)
        finally:
            reset_tenant(pin)
        return VerifiedPrincipal(sub=row["principal"][5:], issuer="lightwork:paired-device", audience="lightwork:companion",
                                 claims={"device_id": ident, "tenant": row["tenant"], "iat": row["issued_at"],
                                         "new_tasks": row.get("new_tasks") is True, "approvals": row.get("approvals") is True})


def claim_work(ident, principal, operation, binding, action, *, receipt, effect_guard):
    """Reserve an intentional work attempt on its existing enrollment, never replay it."""
    if not re.fullmatch(r"[a-f0-9]{32}", operation) or not re.fullmatch(r"[a-f0-9]{64}", binding):
        raise HTTPException(409, "This reviewed request could not be verified.")
    with _locked():
        state = _load()
        row = state["devices"].get(ident)
        if not row or row["principal"] != principal or row["tenant"] != current_tenant_id_strict():
            raise HTTPException(403, "This device no longer belongs to this account and workspace.")
        attempts = row.setdefault("work_attempts", {})
        expected = {"binding": binding, "action": action, "receipt": receipt}
        prior = attempts.get(operation)
        if prior is not None:
            if {key: prior.get(key) for key in expected} != expected:
                raise HTTPException(409, "This original request belongs to different reviewed work.")
            return False
        if len(attempts) >= 1000:
            raise HTTPException(409, "This device's retained work history is full. Nothing was discarded or repeated; use the full dashboard for new work.")
        effect_guard()
        attempts[operation] = {**expected, "at": time.time()}
        _save(state, effect_guard=effect_guard)
        return True


def work_history(ident, principal):
    with _locked():
        row = _load()["devices"].get(ident)
        if not row or row["principal"] != principal or row["tenant"] != current_tenant_id_strict():
            raise HTTPException(403, "This device no longer belongs to this account and workspace.")
        return dict(row.get("work_attempts", {}))


def bind(request, principal):
    if getattr(request.state, "paired_device_verified", False) is not True:
        return False
    tenant = principal.claims["tenant"]
    if current_tenant_id_strict() not in {None, tenant}:
        raise HTTPException(403, "This device belongs to a different workspace.")
    request.state.tenant_pin_token = set_tenant(tenant)
    request.state.paired_device_id = principal.claims["device_id"]
    request.state.workspace_expected_tenant = tenant
    request.state.workspace_tenant_source = "paired_device"
    return True


def renew(token, generation):
    principal = authenticate(token, "POST", "/api/v1/devices/renew")
    with _locked():
        ident, secret = _split(token, PREFIX)
        state, now = _load(), time.time()
        # Removed after it was authenticated above: removal drops the row.
        row = state["devices"].get(ident)
        if row is None:
            raise HTTPException(401, "This device connection was removed or expired.")
        _current(principal.principal, row["issued_at"])
        if row.get("revoked") or min(row["expires_at"], row["enrollment_expires_at"]) <= now:
            raise HTTPException(401, "This device connection was removed or expired.")
        previous = row.get("renewal", {})
        if previous.get("generation") == generation and previous.get("until", 0) > now:
            return {"token": previous["token"], "device": _public(row)}
        if row["generation"] != generation or not hmac.compare_digest(row["secret_hash"], _hash(secret)):
            raise HTTPException(409, "This device connection changed. Pair again if the saved renewal is unavailable.")
        policy = _policy()
        new_secret = secrets.token_urlsafe(32)
        new_token = PREFIX + ident + "." + new_secret
        _audit(principal.principal, "renewed", ident)
        row["renewal"] = {"generation": generation, "previous_hash": row["secret_hash"], "token": new_token, "until": now + 60}
        row.update(secret_hash=_hash(new_secret), generation=generation + 1, issued_at=now,
                   expires_at=min(now + policy["ttl"], row["enrollment_expires_at"]))
        _save(state)
        return {"token": new_token, "device": _public(row)}


def devices(principal):
    _current(principal)
    tenant = current_tenant_id_strict()
    with _locked():
        rows = _load()["devices"].values()
        return [_public(row) for row in rows if row["principal"] == principal and row["tenant"] == tenant]


def revoke(principal, ident):
    # Removal stays available when pairing policy is switched off.
    with _locked():
        _current(principal)
        state = _load()
        row = state["devices"].get(ident)
        if not row or row["principal"] != principal or row["tenant"] != current_tenant_id_strict():
            raise HTTPException(404, "That paired device is unavailable.")
        _audit(principal, "removed", ident)
        row["revoked"] = True
        row.pop("renewal", None)
        _save(state)
        return _public(row)
