"""Authenticated, revision-bound recovery drafts for ordinary app editors."""
from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, HTTPException, Request, Response
from maverick import config
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import _authorization_principal, constant_time_equals, has_permission, require_permission
from .draft_store import DraftConflict, DraftStore

router = APIRouter(prefix="/api/v1/drafts", tags=["draft-recovery"])


class DraftIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(..., ge=0, le=2**31 - 1, strict=True)
    operation_id: str = Field(..., min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    payload: dict | None


class RetireDraftsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: str = Field(..., pattern=r"^[0-9a-f]{64}$")


def context_for(request: Request) -> str:
    principal = _authorization_principal(request)
    mode = "principal"
    if principal is None:
        from ._shared import dashboard_token

        mode = "dashboard-token" if dashboard_token() else "local"
    identity = [current_tenant_id_strict(), mode, principal]
    from maverick import practice

    if practice.active():  # practice drafts, inbox items and labels stay in practice
        identity.append("practice")
    return hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()


def page_context(request: Request) -> dict:
    try:
        # The drafts API needs the operate permission (see _store). Without it a
        # page must not try to save a recovery copy only to be refused.
        if not has_permission(request, "operate"):
            return {"draft_recovery_context": ""}
        if config.config_source_errors(include_tenant=True) or config.get_features().get("draft_recovery") is not True:
            return {"draft_recovery_context": ""}
        return {"draft_recovery_context": context_for(request)}
    except Exception:
        return {"draft_recovery_context": ""}


def _store(request: Request) -> DraftStore:
    require_permission(request, "operate")
    try:
        disabled = bool(config.config_source_errors(include_tenant=True)) or config.get_features().get("draft_recovery") is not True
    except Exception:
        disabled = True
    if disabled:
        raise HTTPException(status_code=403, detail="Draft recovery is disabled in Settings or its configuration is unavailable.")
    context = context_for(request)
    if not constant_time_equals(request.headers.get("X-Lightwork-Draft-Context", ""), context):
        raise HTTPException(status_code=409, detail="The workspace or signed-in account changed. Reload the page before saving or restoring drafts.")
    return DraftStore(context)


async def _call(function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except DraftConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Recovery storage is unavailable. Your current editor contents have been kept.") from exc


@router.get("/storage")
async def draft_storage(request: Request, response: Response) -> dict:
    response.headers["Cache-Control"] = "private, no-store"
    store = _store(request)
    return await _call(store.inventory)


@router.post("/storage/retire")
async def retire_draft_storage(request: Request, body: RetireDraftsIn, response: Response) -> dict:
    response.headers["Cache-Control"] = "private, no-store"
    store = _store(request)
    return await _call(store.retire_discarded, expected_version=body.expected_version)


@router.get("/{slot}")
async def read_draft(request: Request, slot: str, response: Response) -> dict:
    response.headers["Cache-Control"] = "private, no-store"
    store = _store(request)
    return await _call(store.read, slot)


@router.put("/{slot}")
async def save_draft(request: Request, slot: str, body: DraftIn, response: Response) -> dict:
    response.headers["Cache-Control"] = "private, no-store"
    store = _store(request)
    return await _call(store.save, slot, body.payload, expected_revision=body.expected_revision, operation_id=body.operation_id)
