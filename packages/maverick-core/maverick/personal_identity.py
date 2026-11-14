"""Explicit tenant-local links proven from a channel and a named dashboard.

Links grant personal memory scope only, never task ownership, tools or roles.
The channel proof is accepted exclusively by the authenticated server adapter;
the dashboard must separately confirm the observed sender before activation.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time

from .authority_effects import authority_effect_fence
from .crypto_at_rest import seal, unseal
from .file_lock import atomic_write_bytes, cross_process_lock, ensure_private_directory
from .paths import current_tenant_id_strict, data_dir

CHANNELS = frozenset({"slack", "telegram", "discord", "teams", "matrix", "signal", "whatsapp", "sms"})


class IdentityConflict(ValueError):
    pass


def enabled() -> bool:
    from .config import config_source_errors, get_features
    return not config_source_errors() and get_features().get("personal_data_controls") is True


def principal_current(principal: str) -> bool:
    """Dashboard membership is checked again on background channel recall."""
    if not isinstance(principal, str) or not principal.startswith("user:") or len(principal) > 256:
        return False
    try:
        from maverick_dashboard import auth, rbac, scim_groups
        if scim_groups.active_for_principal(principal) is False:
            return False
        tenant = current_tenant_id_strict()
        role = rbac.get_tenant_role(tenant, principal) if tenant else auth.global_role_for_principal(principal)
        return bool(role and "view" in rbac.permissions_for(role))
    except Exception:
        return False


def _path():
    return data_dir("personal-data", "identity-links.enc")


def _read() -> dict:
    try:
        record = json.loads(unseal(_path().read_bytes()).decode())
    except FileNotFoundError:
        return {"tenant": current_tenant_id_strict(), "revision": 0, "links": [], "challenges": []}
    if (not isinstance(record, dict) or record.get("tenant") != current_tenant_id_strict()
            or not isinstance(record.get("links"), list) or not isinstance(record.get("challenges"), list)):
        raise ValueError("Identity links could not be verified. Personal sharing is unavailable.")
    return record


def _write(record, *, actor, action):
    from .audit import audit_event
    # Audit contains no channel identifiers, command or personal content.
    if audit_event("personal_identity_changed", actor=actor, action=action,
                   revision=record["revision"] + 1) is not True:
        raise RuntimeError("The identity change could not be recorded. Nothing was changed.")
    record["revision"] += 1
    atomic_write_bytes(_path(), seal(json.dumps(record, sort_keys=True).encode()), mode=0o600)


def _require(principal):
    if not enabled() or not principal_current(principal):
        raise ValueError("Personal data controls require an enabled feature and current named workspace membership.")


def _lock():
    ensure_private_directory(_path().parent)
    return cross_process_lock(_path(), strict=True)


def account_identity(principal: str, account_sha256: str) -> str:
    if not re.fullmatch(r"[a-f0-9]{64}", account_sha256 or ""):
        raise ValueError("An authenticated channel account receipt is required.")
    return "account:" + account_sha256 + ":person:" + hashlib.sha256(principal.encode()).hexdigest()


def state(principal: str) -> dict:
    _require(principal)
    record = _read()
    now = time.time()
    return {"revision": record["revision"], "channels": sorted(CHANNELS),
            "links": [dict(link) for link in record["links"] if link["principal"] == principal],
            "challenges": [{k: c.get(k) for k in ("id", "channel", "user_id", "sender_id", "expires_at", "status")}
                           for c in record["challenges"] if c["principal"] == principal and c["expires_at"] > now]}


def begin(principal: str, channel: str) -> dict:
    with authority_effect_fence(), _lock():
        _require(principal)
        if channel not in CHANNELS:
            raise ValueError("Choose a supported authenticated messaging channel.")
        record = _read()
        now = time.time()
        record["challenges"] = [c for c in record["challenges"] if c["expires_at"] > now and c["principal"] != principal]
        if len(record["challenges"]) >= 1000:
            raise ValueError("Identity linking is busy. Try again after current requests expire.")
        token = secrets.token_urlsafe(32)
        challenge = {"id": secrets.token_hex(16), "principal": principal, "channel": channel,
                     "digest": hashlib.sha256(token.encode()).hexdigest(), "status": "waiting",
                     "expires_at": now + 600}
        record["challenges"].append(challenge)
        _write(record, actor=principal, action="challenge_created")
        return {"id": challenge["id"], "command": "LIGHTWORK LINK " + token,
                "expires_at": challenge["expires_at"], "channel": channel}


def prove_channel_command(text: str, *, channel: str, user_id: str, sender_id: str | None = None,
                          account_sha256: str | None = None, private_destination: dict | None = None) -> str | None:
    """Called after adapter authentication/tenant admission, before LLM history."""
    # Intercept leading-whitespace variants too, so a link token never reaches
    # LLM history; the strict match below still decides validity.
    if not text.lstrip().startswith("LIGHTWORK LINK"):
        return None
    match = re.fullmatch(r"LIGHTWORK LINK ([A-Za-z0-9_-]{43})", text.strip())
    if not match or channel not in CHANNELS or not user_id or len(user_id) > 256:
        return "This linking command is invalid. Start a fresh link from My Data."
    if not re.fullmatch(r"[a-f0-9]{64}", account_sha256 or ""):
        return "This adapter has no verified account receipt. Linking is unavailable; ask your administrator to review the channel."
    with authority_effect_fence(), _lock():
        if not enabled():
            return "Personal identity linking is disabled by this workspace."
        record = _read()
        digest = hashlib.sha256(match[1].encode()).hexdigest()
        candidate = next((c for c in record["challenges"] if secrets.compare_digest(c["digest"], digest)), None)
        if (candidate is None or candidate["channel"] != channel or candidate["status"] != "waiting"
                or candidate["expires_at"] <= time.time() or not principal_current(candidate["principal"])):
            return "This linking command expired or was already used. Start a fresh link in the same workspace."
        if any(link["channel"] == channel and link["user_id"] == user_id for link in record["links"]):
            return "This channel identity already has a link. Unlink it from its current account first."
        candidate.update(status="proof_received", user_id=user_id, sender_id=sender_id or user_id,
                         account_sha256=account_sha256)
        if channel == "teams" and private_destination is not None:
            from .personal_notification_delivery import teams_destination

            candidate["private_destination"] = teams_destination(private_destination, account_sha256, sender_id)
        _write(record, actor=candidate["principal"], action="channel_proof_received")
    return "Channel proof received. Return to My Data and confirm the displayed channel identity. Nothing is shared yet."


def confirm(principal: str, challenge_id: str, *, expected_revision: int) -> dict:
    with authority_effect_fence(), _lock():
        _require(principal)
        record = _read()
        if record["revision"] != expected_revision:
            raise IdentityConflict("Identity links changed. Refresh and review the displayed sender again.")
        c = next((c for c in record["challenges"] if c["id"] == challenge_id and c["principal"] == principal), None)
        if c is None or c["status"] != "proof_received" or c["expires_at"] <= time.time():
            raise IdentityConflict("This proof is unavailable or expired. Start a fresh link.")
        if any(link["channel"] == c["channel"] and link["user_id"] == c["user_id"] for link in record["links"]):
            raise IdentityConflict("This channel is already linked. Unlink it before changing accounts.")
        if sum(link["principal"] == principal for link in record["links"]) >= 20:
            raise ValueError("Unlink an unused identity before linking another (20 maximum).")
        if len(record["links"]) >= 10000:
            raise ValueError("Workspace identity-link capacity is full. Ask your administrator to retire unused links.")
        record["links"].append({"id": c["id"], "principal": principal, "channel": c["channel"],
                                "user_id": c["user_id"], "sender_id": c["sender_id"],
                                "account_sha256": c["account_sha256"], "verified_at": time.time(),
                                **({"private_destination": c["private_destination"]} if c.get("private_destination") else {})})
        record["challenges"] = [item for item in record["challenges"] if item["id"] != c["id"]]
        _write(record, actor=principal, action="link_confirmed")
        return state(principal)


def unlink(principal: str, link_id: str, *, expected_revision: int) -> dict:
    with authority_effect_fence(), _lock():
        _require(principal)
        record = _read()
        if record["revision"] != expected_revision:
            raise IdentityConflict("Identity links changed. Refresh before unlinking.")
        if not any(link["id"] == link_id and link["principal"] == principal for link in record["links"]):
            raise ValueError("No linked identity belongs to this account.")
        record["links"] = [link for link in record["links"] if not (link["id"] == link_id and link["principal"] == principal)]
        _write(record, actor=principal, action="unlinked")
        return state(principal)


def linked_channels(principal: str) -> list[dict]:
    if not enabled() or not principal_current(principal):
        return []
    return [dict(link) for link in _read()["links"] if link["principal"] == principal]


def principal_for_channel(channel: str, user_id: str) -> str | None:
    if not enabled():
        return None
    for link in _read()["links"]:
        if (link["channel"] == channel and user_id == link["user_id"]
                and principal_current(link["principal"])):
            return link["principal"]
    return None


def linked_principals(*, limit: int = 200, after: str = "") -> list[str]:
    """Bounded current-tenant recipients; callers page by last returned value."""
    if not enabled():
        return []
    principals = sorted({link["principal"] for link in _read()["links"] if link["principal"] > after})
    return [principal for principal in principals if principal_current(principal)][:max(1, min(limit, 1000))]


def recorded_channels(principal: str) -> list[dict]:
    """Exact verified links for governance inventory, including retired members.

    This does not authorize memory recall or delivery. The caller must separately
    authorize installation governance; records never infer an unlinked identity.
    """
    return [dict(link) for link in _read()["links"] if link["principal"] == principal]


def channel_membership_current(channel: str, user_id: str) -> bool:
    """A known linked identity cannot bypass retirement by disabling sharing.

    Unknown/unlinked senders still follow the channel adapter's own ACL. A
    recorded link to a retired or removed named member denies new channel work.
    """
    matches = [link for link in _read()["links"] if link["channel"] == channel and link["user_id"] == user_id]
    return all(principal_current(link["principal"]) for link in matches)
