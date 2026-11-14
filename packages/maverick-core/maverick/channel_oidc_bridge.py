"""Confirmed OIDC identity for first-party, authenticated chat ingress.

Legacy channel account links are deliberately not read here: an administrator's
mapping, an email address, or possession of a code alone is not OIDC proof.
The code observes a provider account; a live OIDC browser session must confirm
that exact observation before it can authorize a channel task.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from .oidc import load_oidc_config, validate_subject
from .paths import current_tenant_id_strict, maverick_home

CHANNELS = frozenset({"slack", "teams"})
CHALLENGE_TTL = 10 * 60
MAX_STORE_BYTES = 4 * 1024 * 1024
MAX_CHALLENGES = 1000
MAX_LINKS = 5000
_ACCOUNT_SHA = re.compile(r"[a-f0-9]{64}\Z")
_PROVIDER_ID = re.compile(r"[A-Za-z0-9._:@-]{1,256}\Z")
_ENTRA_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_LOCAL_LOCK = threading.RLock()


class BridgeError(ValueError):
    """The bridge cannot prove or safely change this identity."""


def store_path() -> Path:
    return maverick_home() / "channel-oidc-bridge.json"


def _installation() -> str:
    # A copied link file is not an authority on another installation. A moved
    # home requires deliberate relinking; replicas sharing one home agree.
    return hashlib.sha256(str(maverick_home().resolve()).encode()).hexdigest()


def _workspace() -> str:
    from .paths import tenant_by_user_enabled

    if tenant_by_user_enabled():
        raise BridgeError("Chat account linking needs a workspace-bound bot installation.")
    return current_tenant_id_strict() or ""


@contextmanager
def _locked():
    path = store_path()
    ensure_private_directory(path.parent)
    with ExitStack() as stack:
        stack.enter_context(_LOCAL_LOCK)
        stack.enter_context(cross_process_lock(path, strict=True))
        yield


def _read() -> dict:
    path = store_path()
    try:
        ensure_private_file(path)
        if path.stat().st_size > MAX_STORE_BYTES:
            raise BridgeError("Chat identity records exceed their safe size.")
        raw = atomic_read_text(path)
        if len(raw.encode("utf-8")) > MAX_STORE_BYTES:
            raise BridgeError("Chat identity records exceed their safe size.")
        data = json.loads(raw)
    except FileNotFoundError:
        return {"installation": _installation(), "challenges": {}, "links": {}}
    except BridgeError:
        raise
    except (OSError, ValueError) as exc:
        raise BridgeError("Chat identity records are unavailable.") from exc
    if (not isinstance(data, dict) or data.get("installation") != _installation()
            or not isinstance(data.get("challenges"), dict)
            or not isinstance(data.get("links"), dict)
            or len(data["challenges"]) > MAX_CHALLENGES
            or len(data["links"]) > MAX_LINKS):
        raise BridgeError("Chat identity records are unavailable.")
    return data


def _write(data: dict) -> None:
    if len(data["challenges"]) > MAX_CHALLENGES or len(data["links"]) > MAX_LINKS:
        raise BridgeError("Chat identity records are full. Ask an administrator to review them.")
    raw = json.dumps(data, sort_keys=True, separators=(",", ":"))
    if len(raw.encode("utf-8")) > MAX_STORE_BYTES:
        raise BridgeError("Chat identity records are full. Ask an administrator to review them.")
    atomic_write_text(store_path(), raw)


def _prune(data: dict, now: float) -> None:
    data["challenges"] = {
        key: row for key, row in data["challenges"].items()
        if isinstance(row, dict) and isinstance(row.get("expires_at"), (int, float))
        and row["expires_at"] > now
    }


def _oidc_identity(sub: str, issuer: str, audience: str) -> tuple[str, str, str]:
    try:
        subject = validate_subject(sub)
    except ValueError as exc:
        raise BridgeError("Sign in again before linking a chat account.") from exc
    cfg = load_oidc_config()
    if not cfg.enabled or not cfg.issuer or not cfg.audience:
        raise BridgeError("Single sign-on is not ready for chat linking.")
    if issuer != cfg.issuer or audience != cfg.audience:
        raise BridgeError("Your sign-in provider has changed. Sign in again.")
    return subject, issuer, audience


def _provider_identity(channel: str, account_sha256: str, provider_tenant: str,
                       sender_id: str) -> tuple[str, str, str, str]:
    if channel not in CHANNELS or not _ACCOUNT_SHA.fullmatch(account_sha256 or ""):
        raise BridgeError("This chat message has no verified app receipt.")
    if (not _PROVIDER_ID.fullmatch(provider_tenant or "")
            or not _PROVIDER_ID.fullmatch(sender_id or "")):
        raise BridgeError("This chat message has no verified account identity.")
    if channel == "teams" and (
        not _ENTRA_ID.fullmatch(provider_tenant)
        or not _ENTRA_ID.fullmatch(sender_id)
    ):
        raise BridgeError("Teams did not provide immutable Entra account identity.")
    return channel, account_sha256, provider_tenant, sender_id


def _key(workspace: str, provider: tuple[str, str, str, str]) -> str:
    values = [_installation(), workspace, *provider]
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def _audit(action: str, *, principal: str, channel: str) -> None:
    from .audit import audit_event

    if audit_event("channel_oidc_bridge_changed", actor=principal, action=action,
                   channel=channel) is not True:
        raise BridgeError("The identity change could not be recorded.")


def _record_revocation(action: str, *, principal: str, channel: str) -> None:
    """Audit a revocation that has already taken effect. If the audit cannot be
    written the error says so; repeating the revocation finishes the removal."""
    try:
        _audit(action, principal=principal, channel=channel)
    except BridgeError as exc:
        raise BridgeError("Access was revoked, but the change could not be recorded in the audit log.") from exc


def _membership_current(subject: str, workspace: str) -> bool:
    principal = "user:" + subject
    try:
        from maverick_dashboard import auth, rbac, scim_groups

        if scim_groups.active_for_principal(principal) is False:
            return False
        # Match the dashboard's effective role: an explicit workspace role
        # overrides the global role, while an absent workspace assignment
        # falls back to it. A failed workspace lookup must never fall back.
        if auth.is_dashboard_admin(principal):
            role = "admin"
        elif workspace:
            role = rbac.get_tenant_role(workspace, principal)
            if not role:
                role = auth.global_role_for_principal(principal)
        else:
            role = auth.global_role_for_principal(principal)
        return "operate" in rbac.permissions_for(role)
    except Exception as exc:
        raise BridgeError("Current workspace access could not be checked.") from exc


def begin(sub: str, issuer: str, audience: str, channel: str) -> dict:
    """Issue a code from a signed-in OIDC session; it grants no access yet."""
    subject, iss, aud = _oidc_identity(sub, issuer, audience)
    if channel not in CHANNELS:
        raise BridgeError("Choose Slack or Microsoft Teams.")
    workspace = _workspace()
    if not _membership_current(subject, workspace):
        raise BridgeError("Your current workspace role cannot start chat tasks.")
    now = time.time()
    code = secrets.token_urlsafe(32)
    challenge_id = secrets.token_hex(16)
    with _locked():
        data = _read()
        _prune(data, now)
        # A new request supersedes prior unconfirmed requests for this person.
        data["challenges"] = {
            key: row for key, row in data["challenges"].items()
            if not (row.get("sub") == subject and row.get("channel") == channel
                    and row.get("workspace") == workspace)
        }
        if len(data["challenges"]) >= MAX_CHALLENGES:
            raise BridgeError("Chat linking is busy. Try again later.")
        data["challenges"][challenge_id] = {
            "sub": subject, "issuer": iss, "audience": aud, "channel": channel,
            "workspace": workspace, "digest": hashlib.sha256(code.encode()).hexdigest(),
            "expires_at": now + CHALLENGE_TTL, "status": "waiting",
        }
        _audit("challenge_requested", principal="user:" + subject, channel=channel)
        _write(data)
    return {"id": challenge_id, "code": code, "channel": channel,
            "expires_at": now + CHALLENGE_TTL}


def observe(channel: str, account_sha256: str, provider_tenant: str,
            sender_id: str, text: str) -> str | None:
    """Record sender observed by authenticated first-party channel delivery."""
    if not isinstance(text, str) or not text.strip().startswith("LIGHTWORK CONNECT"):
        return None
    provider = _provider_identity(channel, account_sha256, provider_tenant, sender_id)
    match = re.fullmatch(r"LIGHTWORK CONNECT ([A-Za-z0-9_-]{43})", text.strip())
    if match is None:
        return "That connection code is invalid. Start again from My work."
    digest = hashlib.sha256(match.group(1).encode()).hexdigest()
    now = time.time()
    with _locked():
        data = _read()
        _prune(data, now)
        for row in data["challenges"].values():
            if (not isinstance(row, dict) or row.get("digest") != digest
                    or row.get("channel") != channel or row.get("workspace") != _workspace()
                    or row.get("expires_at", 0) <= now or row.get("status") != "waiting"):
                continue
            row["status"] = "observed"
            row["provider"] = list(provider)
            row.pop("digest", None)
            _audit("account_observed", principal="user:" + row["sub"], channel=channel)
            _write(data)
            return "Account found. Return to My work and confirm it to finish connecting."
    return "That connection code is invalid or has expired. Start again from My work."


def pending(sub: str, issuer: str, audience: str) -> list[dict]:
    subject, iss, aud = _oidc_identity(sub, issuer, audience)
    now, workspace = time.time(), _workspace()
    out = []
    for challenge_id, row in _read()["challenges"].items():
        if (isinstance(row, dict) and row.get("sub") == subject and row.get("issuer") == iss
                and row.get("audience") == aud and row.get("workspace") == workspace
                and row.get("expires_at", 0) > now and row.get("status") == "observed"):
            provider = row.get("provider")
            if isinstance(provider, list) and len(provider) == 4:
                out.append({"id": challenge_id, "channel": row["channel"],
                            "provider_tenant": provider[2], "sender_id": provider[3]})
    return out


def confirm(sub: str, issuer: str, audience: str, challenge_id: str) -> dict:
    subject, iss, aud = _oidc_identity(sub, issuer, audience)
    workspace = _workspace()
    if not _membership_current(subject, workspace):
        raise BridgeError("Your current workspace role cannot start chat tasks.")
    with _locked():
        data = _read()
        _prune(data, time.time())
        row = data["challenges"].get(challenge_id)
        if (not isinstance(row, dict) or row.get("sub") != subject
                or row.get("issuer") != iss or row.get("audience") != aud
                or row.get("workspace") != workspace or row.get("status") != "observed"
                or row.get("expires_at", 0) <= time.time()):
            raise BridgeError("This connection request expired. Start again from My work.")
        provider = _provider_identity(*row["provider"])
        key = _key(workspace, provider)
        old = data["links"].get(key)
        if old and old.get("sub") != subject:
            raise BridgeError("This chat account is connected to someone else. Ask an administrator to review it.")
        if old is None and len(data["links"]) >= MAX_LINKS:
            raise BridgeError("Chat identity records are full. Ask an administrator to review them.")
        linked_at = time.time()
        data["links"][key] = {
            "sub": subject, "issuer": iss, "audience": aud, "workspace": workspace,
            "provider": list(provider), "linked_at": linked_at,
            "status": "pending_audit",
        }
        _audit("link_confirmation_requested", principal="user:" + subject, channel=provider[0])
        # The first durable write is deliberately unusable. If the confirming
        # audit or final activation fails, the challenge remains retryable and
        # the provider account cannot dispatch through an unaudited link.
        _write(data)
        _audit("link_confirmation_recorded", principal="user:" + subject, channel=provider[0])
        data["links"][key]["status"] = "active"
        del data["challenges"][challenge_id]
        _write(data)
    return {"id": key, "channel": provider[0], "sender_id": provider[3]}


def links_for(sub: str, issuer: str, audience: str) -> list[dict]:
    subject, iss, aud = _oidc_identity(sub, issuer, audience)
    workspace = _workspace()
    return [
        {"id": key, "channel": row["provider"][0],
         "provider_tenant": row["provider"][2], "sender_id": row["provider"][3],
         "linked_at": row["linked_at"], "status": row.get("status")}
        for key, row in _read()["links"].items()
        if isinstance(row, dict) and row.get("sub") == subject and row.get("issuer") == iss
        and row.get("audience") == aud and row.get("workspace") == workspace
        and isinstance(row.get("provider"), list) and len(row["provider"]) == 4
    ]


def all_links() -> list[dict]:
    """Operator view of confirmed links for the current deployment workspace."""
    workspace = _workspace()
    return [
        {"id": key, "principal": "user:" + row["sub"],
         "channel": row["provider"][0], "provider_tenant": row["provider"][2],
         "sender_id": row["provider"][3], "linked_at": row["linked_at"],
         "status": row.get("status")}
        for key, row in _read()["links"].items()
        if isinstance(row, dict) and row.get("workspace") == workspace
        and isinstance(row.get("sub"), str)
        and isinstance(row.get("provider"), list) and len(row["provider"]) == 4
    ]


def revoke(link_id: str, *, actor: str) -> bool:
    """Administrator cuts a provider account loose without its owner's session."""
    with _locked():
        data = _read()
        _prune(data, time.time())
        row = data["links"].get(link_id)
        if not isinstance(row, dict) or row.get("workspace") != _workspace():
            return False
        # Revoke first: an audit outage must not leave a compromised chat
        # account able to act. Only a link that is "active" resolves.
        row["status"] = "revoked"
        _write(data)
        _record_revocation("access_revoked", principal=actor, channel=row["provider"][0])
        del data["links"][link_id]
        _write(data)
    return True


def unlink(sub: str, issuer: str, audience: str, link_id: str) -> bool:
    subject, iss, aud = _oidc_identity(sub, issuer, audience)
    with _locked():
        data = _read()
        _prune(data, time.time())
        row = data["links"].get(link_id)
        if (not isinstance(row, dict) or row.get("sub") != subject
                or row.get("issuer") != iss or row.get("audience") != aud
                or row.get("workspace") != _workspace()):
            return False
        row["status"] = "revoked"
        _write(data)
        _record_revocation("access_revoked", principal="user:" + subject, channel=row["provider"][0])
        del data["links"][link_id]
        _write(data)
    return True


def resolve(channel: str, account_sha256: str, provider_tenant: str,
            sender_id: str) -> str | None:
    """Resolve only an active exact match, with current provider and role policy."""
    provider = _provider_identity(channel, account_sha256, provider_tenant, sender_id)
    row = _read()["links"].get(_key(_workspace(), provider))
    if (not isinstance(row, dict) or row.get("status") != "active"
            or row.get("provider") != list(provider)):
        return None
    subject, _, _ = _oidc_identity(row.get("sub"), row.get("issuer"), row.get("audience"))
    principal = "user:" + subject
    try:
        from maverick_dashboard import session_revocation

        if session_revocation.is_revoked(subject, row.get("linked_at")):
            return None
        if not _membership_current(subject, _workspace()):
            return None
    except Exception as exc:
        raise BridgeError("Current workspace access could not be checked.") from exc
    return principal


__all__ = ["BridgeError", "all_links", "begin", "confirm", "links_for", "observe",
           "pending", "resolve", "revoke", "store_path", "unlink"]
