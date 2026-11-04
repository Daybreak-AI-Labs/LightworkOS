"""Ordinary controls for checking the original signing-secret publication."""
from __future__ import annotations

import hmac

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from . import webhook_settings_recovery as source
from .admin_pages import _webhook_operation
from .draft_api import context_for

router = APIRouter(prefix="/settings/webhooks/recovery", tags=["webhook-settings"])
asset_router = APIRouter()


class Check(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    review: str = Field(min_length=1, max_length=4096)
    confirm: bool


def choices(request):
    result = _webhook_operation(request, lambda principal, authorize: source.choices(principal=principal, authorize=authorize))
    return {"context": context_for(request), **result}


def reconcile(request, identity, body):
    from .app import _require_same_origin

    _require_same_origin(request)
    auth.require_global_permission(request, "admin")
    if not hmac.compare_digest(body.context, context_for(request)):
        raise HTTPException(409, "Your account or workspace changed. Refresh before checking this change.")
    if body.confirm is not True:
        raise HTTPException(422, "Review and confirm the saved change check.")
    return _webhook_operation(request, lambda principal, authorize: source.reconcile(identity, body.review, principal=principal, authorize=authorize))


def _call(function):
    try:
        return function()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "The saved change history could not be verified. No secret was saved again. Refresh before trying another check.") from exc


@router.get("")
def saved_changes(request: Request):
    return JSONResponse(_call(lambda: choices(request)), headers={"Cache-Control": "private, no-store"})


@router.post("/{identity}/check")
def check_saved_change(request: Request, identity: str, body: Check):
    return JSONResponse(_call(lambda: reconcile(request, identity, body)), headers={"Cache-Control": "private, no-store"})


@asset_router.get("/static/lightwork-webhook-recovery.js")
def recovery_asset():
    from .app import _STATIC_DIR

    return FileResponse(_STATIC_DIR / "lightwork-webhook-recovery.js", media_type="application/javascript",
                        headers={"Cache-Control": "public, max-age=300"})
