"""The consent publication signing key: create or replace it, and give it to websites.

A global administrator creates (or replaces) the installation's signing key on
the Banner and Preference Center page. The key is generated here, stored
sealed with the deployment key in the dashboard settings overlay
(``[consent_publication_signing] keyring``, read by
:mod:`maverick.consent_publication_signing`) and never returned, logged or
shown: people see the active workspace's public key by its fingerprint and
download it for their websites. Replacing the key keeps the replaced one only
to check settings it already signed. Every change writes one audit row, and
is undone if the audit row cannot be written.
``MAVERICK_CONSENT_PUBLICATION_SIGNING_KEY`` wins when set, and then the key
cannot be changed here.
"""
from __future__ import annotations

import base64
import copy
import json
import secrets
import time

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict

from . import settings_store
from .auth import caller_principal, require_global_permission, require_permission

router = APIRouter(prefix="/consent/publishing/signing-key", tags=["consent-publishing"])


class RotateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    confirm: bool


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="Select a workspace before using the signing key.",
        )
    return tenant


def _ring(data: dict) -> dict:
    from maverick import consent_publication_signing as signing

    section = data.get(signing.SECTION)
    ring = section.get(signing.KEYRING_KEY) if isinstance(section, dict) else None
    return ring if isinstance(ring, dict) else {}


def key_state(tenant_id: str) -> dict:
    """What the page may show: public material only, never a private key."""
    from maverick import consent_publication_signing as signing

    custody = signing.custody()
    ring = _ring(settings_store.load_overlay())
    state: dict = {
        "required": signing.signing_required(),
        "managed_by_server": custody.managed_by_server,
        "configured": bool(custody.roots),
        "rotated_at": ring.get("rotated_at")
        if isinstance(ring.get("rotated_at"), (int, float)) else None,
        "retired_keys": max(len(custody.roots) - 1, 0),
        "key": None,
    }
    if custody.roots:
        try:
            state["key"] = signing.public_key_document(custody.signer_for(tenant_id))
        except (signing.PublicationSigningUnavailable, ImportError):
            state["configured"] = False
    return state


def _private(response: Response) -> None:
    response.headers["Cache-Control"] = "private, no-store"


@router.get("")
def overview(request: Request, response: Response) -> dict:
    require_permission(request, "operate")
    _private(response)
    return key_state(_tenant_id())


@router.get("/public-key")
def download_public_key(request: Request) -> Response:
    """The active workspace's public key as a file for its websites."""
    require_permission(request, "operate")
    from . import report_downloads

    context = report_downloads.capture(request, "public_key")
    key = report_downloads.current_public_key()
    if key is None:
        raise HTTPException(status_code=404, detail="There is no signing key yet.")
    response = Response(
        content=json.dumps(key, indent=2, sort_keys=True) + "\n",
        media_type="application/json",
        headers={
            "Content-Disposition":
                f'attachment; filename="lightwork-consent-signing-key-{key["key_id"]}.json"',
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
    revision = report_downloads.public_key_revision(key)
    if revision != report_downloads.public_key_revision(report_downloads.current_public_key()):
        raise HTTPException(409, "The signing key changed while preparing the file. Try the current download again.")
    response.headers[report_downloads.KEY_HEADER] = revision
    return report_downloads.finish(request, "public_key", context, response)


@router.post("/rotate")
def rotate(request: Request, response: Response, payload: RotateIn) -> dict:
    """Create the signing key, or replace it. Global administrators only; audited."""
    require_global_permission(request, "admin")
    _private(response)
    from .app import _require_same_origin

    _require_same_origin(request)
    if payload.confirm is not True:
        raise HTTPException(422, "Review and confirm the key change.")
    tenant = _tenant_id()
    from maverick import config
    from maverick import consent_publication_signing as signing
    from maverick.audit import AuditRefused, EventKind, audit_event

    if signing.custody().managed_by_server:
        raise HTTPException(409, "The signing key is set on the server, so it can't be changed here.")
    actor = caller_principal(request) or "local administrator"
    with settings_store._locked(strict=True):
        before = settings_store._load_overlay_for_update()
        data = copy.deepcopy(before)
        section = data.setdefault(signing.SECTION, {})
        if not isinstance(section, dict):
            raise HTTPException(503, "Settings could not be saved right now. Nothing was changed.")
        now = time.time()
        old = _ring(data)
        current = old.get("current") if isinstance(old.get("current"), dict) else None
        retired = [item for item in (old.get("previous") or []) if isinstance(item, dict)]
        if current is not None:
            retired.insert(0, {"id": current.get("id"), "root": current.get("root"),
                               "retired_at": now})
        root = "base64:" + base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        section[signing.KEYRING_KEY] = {
            "current": {"id": f"root-{int(now)}-{secrets.token_hex(4)}",
                        "root": settings_store._seal_global_secret(root), "created_at": now},
            "previous": [
                {"id": str(item.get("id")),
                 "root": settings_store._seal_global_secret(item.get("root")),
                 "retired_at": float(item.get("retired_at") or now)}
                for item in retired[: signing.MAX_PREVIOUS_ROOTS]
                if isinstance(item.get("root"), str)
            ],
            "rotated_at": now,
        }
        settings_store._write(data)
        config.reset_config_cache()
        state = key_state(tenant)
        try:
            audit_event(EventKind.SETTING_CHANGED, agent="dashboard", _global=True, actor=actor,
                        section=signing.SECTION, key="signing_key",
                        old="set" if current is not None else "not set",
                        new="replaced" if current is not None else "created",
                        key_id=(state["key"] or {}).get("key_id"), confirmed=True)
        except AuditRefused as exc:
            settings_store._write(before)
            config.reset_config_cache()
            raise HTTPException(503, "The change could not be recorded, so it was undone.") from exc
    return state


__all__ = ["key_state", "router"]
