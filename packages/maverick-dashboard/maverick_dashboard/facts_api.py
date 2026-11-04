"""Scoped fact browsing, exact history and optimistic deletion."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Query, Request, Response
from maverick.fact_revision import FactConflict, is_private_fact_key
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_permission
from .draft_api import context_for

router = APIRouter(prefix="/facts", tags=["facts"])


@router.get("/records")
def records(request: Request, response: Response, query: str = Query("", max_length=200),
            source: str = Query("", max_length=200), updated_before: float | None = None,
            tag: str = Query("", max_length=64), snapshot: str = Query("", max_length=64),
            offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100)):
    require_permission(request, "view")
    from ._shared import _world
    world = _world()
    ctx = context_for(request)
    binding = [ctx, query, source, updated_before, tag, world.fact_catalog_revision()]
    current = hashlib.sha256(json.dumps(binding).encode()).hexdigest()
    if snapshot and snapshot != current:
        raise HTTPException(409, "Facts changed. Search again to begin a current page sequence.")
    if offset and not snapshot:
        raise HTTPException(409, "Begin with the first page before browsing more facts.")
    items = world.fact_records(query=query, source=source, updated_before=updated_before,
                               tag=tag, offset=offset, limit=limit + 1, shared_only=True)
    if binding[-1] != world.fact_catalog_revision() or ctx != context_for(request):
        raise HTTPException(409, "Facts or access changed while loading. Search again.")
    response.headers["Cache-Control"] = "private, no-store"
    return {"context": ctx, "snapshot": current, "tags_enabled": tags_enabled(), "items": items[:limit],
            "has_more": len(items) > limit, "offset": offset, "limit": limit}


@router.get("/record")
def record(request: Request, response: Response, key: str = Query(..., max_length=200)):
    require_permission(request, "view")
    if is_private_fact_key(key):
        raise HTTPException(404, "This fact is not available in shared workspace facts.")
    from ._shared import _world
    world = _world()
    item = world.fact_record(key)
    if item is None:
        raise HTTPException(404, "This fact is no longer saved in this workspace.")
    response.headers["Cache-Control"] = "private, no-store"
    return {"context": context_for(request), "tags_enabled": tags_enabled(), "item": item,
            "history": [asdict(version) for version in world.fact_history(key, limit=50, owned_only=True)],
            "history_notice": "Removing stops new recall. Recorded history may remain under workspace retention policy; it is not permanent erasure."}


def tags_enabled() -> bool:
    from maverick.fact_revision import tags_enabled as enabled
    return enabled()


class TagsIn(BaseModel):
    key: str = Field(min_length=1, max_length=200)
    tags: list[str] = Field(max_length=20)
    expected_revision: int = Field(ge=1)
    context: str = Field(min_length=64, max_length=64)


def update_fact_tags(request: Request, key: str, tags: list[str],
                     expected_revision: int, context: str) -> int:
    require_permission(request, "operate")
    if not tags_enabled():
        raise HTTPException(409, "An administrator can enable fact tags in Memory & learning settings.")
    if context != context_for(request):
        raise HTTPException(409, "Your account or workspace changed. Reload before editing tags.")
    if is_private_fact_key(key):
        raise HTTPException(404, "This fact is not available in shared workspace facts.")
    from ._shared import _world
    world = _world()
    item = world.fact_record(key)
    if item is None:
        raise HTTPException(404, "This fact is no longer saved.")
    try:
        return world.upsert_fact(key, item["value"], episode_id=item["source_episode_id"],
                                 source=item["source"], trust_tier=item["trust_tier"],
                                 sensitivity=item["sensitivity"], tags=tags,
                                 expected_revision=expected_revision)
    except FactConflict as exc:
        raise HTTPException(409, "This fact changed. Review its current detail and tags before editing.") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.patch("/tags")
def set_tags(request: Request, payload: TagsIn):
    revision = update_fact_tags(request, **payload.model_dump())
    return {"context": context_for(request), "revision": revision}


def remove_fact(request: Request, key: str, expected_revision: int, context: str) -> None:
    """One native scope/CAS boundary for direct deletion and reviewed Copilot."""
    require_permission(request, "operate")
    name = (key or "").strip()
    if not name:
        raise HTTPException(400, "fact name is required")
    if is_private_fact_key(name):
        raise HTTPException(404, "This fact is not available in shared workspace facts.")
    if context != context_for(request):
        raise HTTPException(409, "Your account or workspace changed. Reload before removing.")
    from ._shared import _world
    try:
        removed = _world().delete_fact(name, expected_revision=expected_revision)
    except FactConflict as exc:
        raise HTTPException(409, "This fact changed. Review its current value before removing.") from exc
    if not removed:
        raise HTTPException(404, "no such fact")


@router.delete("/{key:path}", status_code=204)
async def delete_fact(request: Request, key: str, expected_revision: int = Query(..., ge=1),
                      context: str = Query(..., min_length=64, max_length=64)) -> Response:
    await run_in_threadpool(remove_fact, request, key, expected_revision, context)
    return Response(status_code=204)


__all__ = ["router"]
