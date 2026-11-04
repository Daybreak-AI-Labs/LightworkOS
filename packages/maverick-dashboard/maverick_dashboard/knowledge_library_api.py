"""Knowledge library: see collections, load starter content, rebuild search.

These were command-line only (``maverick knowledge collections|seed|reindex``).
They act on the active workspace's knowledge base only; loading starter
content and rebuilding the search index need administrator access.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_permission

router = APIRouter(prefix="/knowledge/library", tags=["knowledge-library"])


class SeedIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    collection: str | None = Field(default=None, min_length=1, max_length=128)


def _open() -> Any | None:
    from maverick.knowledge_admin import open_knowledge_base

    return open_knowledge_base()


def _overview() -> dict[str, object]:
    from maverick.knowledge_seed import available_corpora

    starters = available_corpora()
    kb = _open()
    if kb is None:
        return {"enabled": False, "collections": [], "starter_content": starters}
    try:
        collections = []
        for name in kb.collections():
            count = kb.store.count(name) if hasattr(kb.store, "count") else None
            collections.append({"name": name, "chunks": count})
    finally:
        kb.close()
    present = {item["name"] for item in collections}
    for starter in starters:
        starter["loaded"] = starter["collection"] in present
    return {"enabled": True, "collections": collections, "starter_content": starters}


def _seed(collection: str | None) -> dict[str, int]:
    from maverick.knowledge_seed import available_corpora, seed_corpora

    if collection is not None and collection not in {
        item["collection"] for item in available_corpora()
    }:
        raise LookupError("unknown starter collection")
    kb = _open()
    if kb is None:
        raise RuntimeError("knowledge is turned off")
    try:
        return seed_corpora(kb, only=collection)
    finally:
        kb.close()


async def _call(function, *args):
    try:
        return await run_in_threadpool(function, *args)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="knowledge collection not found") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="knowledge is unavailable") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="knowledge request is invalid") from exc
    except Exception as exc:  # noqa: BLE001 - never disclose store internals
        raise HTTPException(status_code=503, detail="knowledge is unavailable") from exc


@router.get("")
async def overview(request: Request) -> dict[str, object]:
    """Collections in this workspace and the starter content that can be loaded."""
    require_permission(request, "view")
    return await _call(_overview)


@router.post("/seed")
async def seed(request: Request, body: SeedIn) -> dict[str, object]:
    """Load (or refresh) the shipped starter content; repeat loads replace, not duplicate."""
    require_permission(request, "admin")
    report = await _call(_seed, body.collection)
    return {"loaded": report, "chunks": sum(report.values())}


class ReindexIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    job_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    review: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirmed: bool


class JobActionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirmed: bool


def _reindex_authority(request, expected_context=None):
    from .draft_api import context_for
    require_permission(request, "admin")
    current = context_for(request)
    if expected_context is not None and current != expected_context:
        raise HTTPException(409, "Your account or workspace changed. Reload before rebuilding.")
    return current


def _reindex_call(function, *args, **kwargs):
    from maverick.knowledge_admin import open_knowledge_base
    kb = open_knowledge_base(require_existing=True)
    if kb is None:
        raise HTTPException(409, "Document search is turned off. An administrator can enable it in Knowledge settings.")
    try:
        return function(kb, *args, **kwargs)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    finally:
        kb.close()


@router.get("/collections/{collection}/reindex-review")
async def reindex_review(request: Request, response: Response, collection: str):
    from maverick.knowledge_reindex_jobs import preview
    context = _reindex_authority(request)
    response.headers["Cache-Control"] = "private, no-store"
    review = await run_in_threadpool(_reindex_call, preview, collection)
    _reindex_authority(request, context)
    return {"context": context, "review": review}


@router.get("/reindex-jobs")
def reindex_jobs(request: Request, response: Response):
    from maverick.knowledge_reindex_jobs import list_jobs
    context = _reindex_authority(request)
    response.headers["Cache-Control"] = "private, no-store"
    return {"context": context, "jobs": list_jobs(context)}


def _run_reindex(request, context, job_id):
    from maverick.knowledge_reindex_jobs import run
    _reindex_call(run, context=context, job_id=job_id,
                  authority=lambda: _reindex_authority(request, context))


@router.post("/collections/{collection}/reindex", status_code=202)
async def reindex(request: Request, collection: str, body: ReindexIn, background_tasks: BackgroundTasks):
    from maverick.knowledge_reindex_jobs import start
    _reindex_authority(request, body.context)
    if not body.confirmed:
        raise HTTPException(400, "Review and confirm the collection and limits before rebuilding.")
    job = await run_in_threadpool(_reindex_call, start, context=body.context, job_id=body.job_id,
                                 collection=collection, review=body.review)
    if job["state"] == "queued":
        background_tasks.add_task(_run_reindex, request, body.context, body.job_id)
    return {"context": body.context, "job": job}


@router.post("/reindex-jobs/{job_id}/{action}")
def reindex_action(request: Request, job_id: str, action: str, body: JobActionIn, background_tasks: BackgroundTasks):
    from maverick.knowledge_reindex_jobs import archive, cancel, list_jobs
    _reindex_authority(request, body.context)
    if not body.confirmed:
        raise HTTPException(400, "Review this rebuild before choosing an action.")
    if action in {"cancel", "archive"}:
        try:
            function = archive if action == "archive" else cancel
            return {"context": body.context, "job": function(body.context, job_id)}
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(404, "This rebuild is not available here. Refresh the list to see the latest.") from exc
    if action != "resume":
        raise HTTPException(404, "Choose a supported rebuild action.")
    job = next((row for row in list_jobs(body.context) if row["job_id"] == job_id), None)
    if job is None:
        raise HTTPException(404, "This rebuild is not available here. Refresh the list to see the latest.")
    if job["state"] not in {"queued", "running", "publishing"}:
        raise HTTPException(409, "This rebuild has stopped. Review the collection before starting a new rebuild.")
    background_tasks.add_task(_run_reindex, request, body.context, job_id)
    return {"context": body.context, "job": job}


__all__ = ["router"]
