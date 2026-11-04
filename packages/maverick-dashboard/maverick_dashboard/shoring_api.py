"""Operator API for Autonomous Shoring: the Book of Work + measured SLAs.

The Book of Work is a tenant-scoped governed store (``maverick.shoring``), not
a world-model migration. Reads (``GET`` book/sla) need ``view``; writes
(``POST``/``DELETE`` a function) need ``operate`` -- the same floors the
dashboard uses elsewhere. Mutating requests additionally pass the app's global
same-origin CSRF guard (as every other ``/api/v1`` mutation does), so a
cross-site page cannot drive the book.

SLA actuals and the exception-desk counts are computed READ-ONLY from real
completed work in the Operating Record; nothing here tunes the workforce.
"""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import _world
from .auth import goal_owner_filter, require_permission

BOOK_SCHEMA = "lightwork.shoring-book.v1"
SLA_SCHEMA = "lightwork.shoring-sla.v1"

# The measurable SLA metrics. Kept in lockstep with maverick.shoring.METRICS so
# a new metric there is a deliberate, single-line change here too.
Metric = Literal["throughput_per_day", "max_exception_rate_pct",
                 "max_turnaround_hours"]

Key = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=64,
                                       pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")]
Bounded = Annotated[str, StringConstraints(strict=True, max_length=400)]
Lifecycle = Literal["scoping", "demonstrating", "running", "proving"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SLAIn(_StrictModel):
    name: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=64)]
    metric: Metric
    target: float = Field(ge=0, le=1_000_000)


class FunctionIn(_StrictModel):
    key: Key
    name: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=400)]
    department: Bounded = ""
    scope: Bounded = ""
    status: Lifecycle = "scoping"
    owner: Bounded = ""
    slas: list[SLAIn] = Field(default_factory=list, max_length=12)


def _require_enabled() -> None:
    from maverick import shoring

    if not shoring.enabled():
        raise HTTPException(
            status_code=404,
            detail="This feature is turned off.")


def _book(owner) -> dict:
    from maverick import shoring

    return {"schema": BOOK_SCHEMA, "functions": shoring.book_status(_world(), owner=owner)}


def _sla(key: str, owner) -> dict:
    from maverick import shoring

    fn = next((f for f in shoring.load(strict=True) if f.key == key), None)
    if fn is None:
        raise HTTPException(status_code=404, detail="That business area is not in the book of work.")
    return {"schema": SLA_SCHEMA, "function": shoring.function_status(fn, _world(), owner=owner)}


def _upsert(body: FunctionIn, owner) -> dict:
    from maverick import shoring

    fn = shoring.Function(
        key=body.key, name=body.name, department=body.department,
        scope=body.scope, status=body.status, owner=body.owner,
        slas=[shoring.SLATarget(s.name, s.metric, s.target) for s in body.slas],
    )
    shoring.upsert(fn)
    return {"schema": SLA_SCHEMA, "function": shoring.function_status(fn, _world(), owner=owner)}


def _remove(key: str) -> dict:
    from maverick import shoring

    if not shoring.remove(key):
        raise HTTPException(status_code=404, detail="That business area is not in the book of work.")
    return {"removed": key}


async def _call(function, *args):
    try:
        return await run_in_threadpool(function, *args)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=503,
                            detail="The book of work is not available right now.") from exc


def create_shoring_router() -> APIRouter:
    router = APIRouter(prefix="/shoring", tags=["shoring"])

    @router.get("/book")
    async def book(request: Request):
        require_permission(request, "view")
        _require_enabled()
        return await _call(_book, goal_owner_filter(request))

    @router.get("/sla")
    async def sla(request: Request, key: Key):
        require_permission(request, "view")
        _require_enabled()
        return await _call(_sla, key, goal_owner_filter(request))

    @router.post("/function")
    async def upsert_function(request: Request, body: FunctionIn):
        # Writing the book of work is an operate action (and same-origin-gated
        # centrally like every /api/v1 mutation).
        require_permission(request, "operate")
        _require_enabled()
        return await _call(_upsert, body, goal_owner_filter(request))

    @router.post("/turn-on")
    async def turn_on(request: Request):
        """Turn the shoring pages back on from the app (administrators)."""
        from maverick import config, shoring

        from . import settings_store
        from .auth import require_global_permission

        require_global_permission(request, "admin")
        from maverick.audit import AuditRefused

        from .settings_audit import record_setting_change

        was_on = bool(shoring.enabled())
        await run_in_threadpool(settings_store.set_section_enable, "shoring", True)
        config.reset_config_cache()
        if not shoring.enabled():
            raise HTTPException(
                status_code=409,
                detail="This setting is controlled by your installation and cannot be changed here.")
        if not was_on:
            try:
                await run_in_threadpool(lambda: record_setting_change(
                    request, section="shoring", key="enable", old=False, new=True))
            except AuditRefused as exc:
                # No change without a record of it: turn it back off.
                await run_in_threadpool(settings_store.set_section_enable, "shoring", False)
                config.reset_config_cache()
                raise HTTPException(
                    status_code=503,
                    detail="The change could not be recorded, so it was undone.") from exc
        return {"enabled": True}

    @router.delete("/function/{key}")
    async def delete_function(request: Request, key: Key):
        require_permission(request, "operate")
        _require_enabled()
        return await _call(_remove, key)

    return router


router = create_shoring_router()

__all__ = ["create_shoring_router", "router", "FunctionIn", "SLAIn",
           "BOOK_SCHEMA", "SLA_SCHEMA"]
