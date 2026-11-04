"""Rotate the key behind vendor portal links, with a grace period.

Every vendor portal address is derived from this installation's portal
routing key. Rotating it makes new addresses; the previous key keeps opening
the old addresses until its grace period ends, so vendors are not cut off
mid-questionnaire. The keyring (current key, up to two previous keys with an
end time, a revision) is stored sealed with the deployment key in the
dashboard overlay, like every other dashboard secret, and read by
``third_party_collaboration_composition._configured_routing_key``. No key is
ever returned. ``MAVERICK_THIRD_PARTY_PORTAL_ROUTING_KEY`` wins when set, and
then nothing can be rotated here.
"""
from __future__ import annotations

import copy
import os
import secrets
import time

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict

from . import settings_store
from .auth import caller_principal, require_global_permission
from .third_party_collaboration_composition import (
    KEYRING_KEY,
    KEYRING_SECTION,
    MAX_PREVIOUS_KEYS,
    ROUTING_KEY_ENV,
)

router = APIRouter(prefix="/api/v1/third-party/portal-routing-key", tags=["third-party"])

# Hours the previous key keeps opening existing vendor links.
GRACE_HOURS = (0, 1, 24, 72, 168, 720)


class RotateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    confirm: bool
    grace_hours: int


def _server_managed() -> bool:
    return bool(os.environ.get(ROUTING_KEY_ENV))


def _ring(data: dict) -> dict:
    section = data.get(KEYRING_SECTION)
    ring = section.get(KEYRING_KEY) if isinstance(section, dict) else None
    return ring if isinstance(ring, dict) else {}


def _live_previous(ring: dict, now: float) -> list[dict]:
    return [item for item in ring.get("previous") or []
            if isinstance(item, dict) and isinstance(item.get("key"), str)
            and isinstance(item.get("until"), (int, float)) and not isinstance(item["until"], bool)
            and item["until"] > now]


def key_state() -> dict:
    """What the page may show: never a key, its fingerprint or its revision."""
    now = time.time()
    ring = _ring(settings_store.load_overlay())
    previous = _live_previous(ring, now)
    return {
        "managed_by_server": _server_managed(),
        "configured": bool(ring.get("current")) or _server_managed(),
        "rotated_at": ring.get("rotated_at") if isinstance(ring.get("rotated_at"), (int, float)) else None,
        "previous_keys_open": len(previous),
        "grace_until": max((item["until"] for item in previous), default=None),
        "grace_hours": list(GRACE_HOURS),
    }


def _admin(request: Request, response: Response) -> str:
    require_global_permission(request, "admin")
    response.headers["Cache-Control"] = "private, no-store"
    return caller_principal(request) or "local administrator"


@router.get("")
def overview(request: Request, response: Response) -> dict:
    _admin(request, response)
    return key_state()


@router.post("/rotate")
def rotate(request: Request, response: Response, payload: RotateIn) -> dict:
    """Make a new portal routing key; the previous one keeps opening existing
    links for ``grace_hours`` (0 ends them now). Audited; no key is shown."""
    actor = _admin(request, response)
    from .app import _require_same_origin
    _require_same_origin(request)
    if payload.confirm is not True:
        raise HTTPException(422, "Review and confirm the key change.")
    if payload.grace_hours not in GRACE_HOURS:
        raise HTTPException(422, "Choose how long existing vendor links keep working.")
    if _server_managed():
        raise HTTPException(409, "The portal link key is set on the server, so it can't be changed here.")
    from maverick import config
    from maverick.audit import AuditRefused, EventKind, audit_event

    with settings_store._locked(strict=True):
        before = settings_store._load_overlay_for_update()
        data = copy.deepcopy(before)
        section = data.setdefault(KEYRING_SECTION, {})
        if not isinstance(section, dict):
            raise HTTPException(503, "Settings could not be saved right now. Nothing was changed.")
        now = time.time()
        old = _ring(data)
        previous = _live_previous(old, now)
        if isinstance(old.get("current"), str) and payload.grace_hours:
            previous.insert(0, {"key": old["current"], "until": now + payload.grace_hours * 3600})
        section[KEYRING_KEY] = {
            "revision": f"rev-{int(now)}-{secrets.token_hex(4)}",
            "current": settings_store._seal_global_secret(secrets.token_urlsafe(48)),
            "previous": [{"key": settings_store._seal_global_secret(item["key"]),
                          "until": float(item["until"])} for item in previous[:MAX_PREVIOUS_KEYS]],
            "rotated_at": now,
        }
        settings_store._write(data)
        config.reset_config_cache()
        try:
            audit_event(EventKind.SETTING_CHANGED, agent="dashboard", _global=True, actor=actor,
                        section=KEYRING_SECTION, key="routing_key",
                        old="set" if old.get("current") else "not set", new="rotated",
                        grace_hours=payload.grace_hours, confirmed=True)
        except AuditRefused as exc:
            settings_store._write(before)
            config.reset_config_cache()
            raise HTTPException(503, "The change could not be recorded, so it was undone.") from exc
    return key_state()


__all__ = ["router", "key_state", "GRACE_HOURS"]
