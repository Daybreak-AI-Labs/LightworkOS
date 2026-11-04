"""Global-administrator review of provider accounting, with no provider retry."""
from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from maverick import backup, practice_costs, provider_cost_cap, workspace_recovery
from maverick import provider_spending_recovery as spending
from maverick.governed_operations import digest
from maverick.privacy_ops import RecordConflict
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import _authorization_principal, constant_time_equals, require_global_permission
from .recovery_mode import enabled, isolated

router = APIRouter()
BASE = "/api/v1/recovery/provider-spending"


def _admit(request, *, mutation=False):
    require_global_permission(request, "admin")
    actor = _authorization_principal(request) or "local"
    context = digest([spending.target(), actor])
    supplied = request.headers.get("X-Lightwork-Spending-Context")
    if (mutation or supplied is not None) and not constant_time_equals(supplied or "", context):
        raise HTTPException(409, "Your account or workspace changed. Reload provider spending before continuing.")
    return actor, context


async def _call(function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except (spending.SpendingReviewError, provider_cost_cap.ProviderAccountingUnavailable,
            RecordConflict, workspace_recovery.RecoveryError, backup.BackupError) as exc:
        raise HTTPException(409, str(exc)) from exc
    except (OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(503, "Accounting storage could not complete this step. Retained charges and review evidence have been kept.") from exc


def _json(value):
    return Response(json.dumps(value, allow_nan=False), media_type="application/json",
                    headers={"Cache-Control": "private, no-store"})


class HoldIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str = Field(min_length=1, max_length=128)
    period: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}(?:-[0-9]{2})?$")
    receipt: str = Field(min_length=1, max_length=192)
    actual: float = Field(ge=0, allow_inf_nan=False, strict=True)
    evidence: str = Field(min_length=8, max_length=2000)


class TotalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str = Field(min_length=1, max_length=128)
    period: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}(?:-[0-9]{2})?$")
    confirmed: float = Field(ge=0, allow_inf_nan=False, strict=True)


class RepairIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    imported: str = Field(pattern=r"^PAR-[A-Za-z0-9_-]+$")
    totals: list[TotalIn] = Field(min_length=1, max_length=500)
    evidence: str = Field(min_length=8, max_length=2000)
    receipts_complete: bool = Field(strict=True)


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    review: str = Field(pattern=r"^PAR-[A-Za-z0-9_-]+$")
    confirm: bool = Field(strict=True)


def _freshness() -> tuple[bool, float | None]:
    """Whether the ledger is the shared database (which has no readable time)
    and, if not, when spending was last recorded. File and database reads, so
    the page runs this off the event loop."""
    try:
        shared = provider_cost_cap._shared_world() is not None
    except provider_cost_cap.ProviderAccountingUnavailable:
        shared = True
    return shared, None if shared else provider_cost_cap.recorded_at()


@router.get("/provider-spending")
async def page(request: Request):
    _admit(request)
    from starlette.concurrency import run_in_threadpool

    from . import settings_store
    from .app import templates

    shared, recorded_at = await run_in_threadpool(_freshness)
    response = templates.TemplateResponse(request, "provider_spending.html", {
        "recovery_mode": enabled(request.app),
        "provider_options": [{"name": p["name"], "label": p["label"]} for p in settings_store.PROVIDERS],
        # A shared database ledger has no readable time: say nothing rather than guess.
        "spend_freshness_known": not shared,
        "spend_recorded_at": recorded_at,
        "practice_cost": ((await run_in_threadpool(practice_costs.provider_share, provider_cost_cap.period_key()))
                          or {}).get("text", ""),
    })
    response.headers["Cache-Control"] = "private, no-store"
    return response


@router.get("/static/lightwork-provider-spending.js")
@router.get("/static/lightwork-provider-spending.css")
async def controller(request: Request):
    from pathlib import Path
    name = request.url.path.rsplit("/", 1)[-1]
    return FileResponse(Path(__file__).parent / "static" / name, media_type="text/css" if name.endswith(".css") else "application/javascript",
                        headers={"Cache-Control": "public, max-age=300"})


@router.get(BASE)
async def status(request: Request, period: str | None = Query(default=None, pattern=r"^[0-9]{4}-[0-9]{2}(?:-[0-9]{2})?$"),
                 provider: str | None = Query(default=None, max_length=128),
                 offset: int = Query(default=0, ge=0, le=100000), limit: int = Query(default=100, ge=1, le=100)):
    _, context = _admit(request)
    report = await _call(spending.status, period, provider=provider, offset=offset, limit=limit)
    # Practice calls are real provider charges already in these totals; say how much.
    report["practice"] = await run_in_threadpool(practice_costs.provider_share, report.get("period") or period
                                                 or provider_cost_cap.period_key())
    return _json({**report, "context": context,
                  "isolated": isolated(request.app),
                  "expected_tenant": getattr(request.state, "workspace_expected_tenant", "")})


@router.get(BASE + "/reviews")
async def open_reviews(request: Request):
    """This administrator's unfinished reviews, so the page can offer them in a
    list instead of asking for a typed reference. Read-only."""
    actor, context = _admit(request, mutation=True)
    return _json({"reviews": await _call(spending.open_reviews, actor=actor, context=context)})


@router.get(BASE + "/review/{identifier}")
async def retained_review(request: Request, identifier: str):
    actor, context = _admit(request, mutation=True)
    return _json(await _call(spending.review, identifier, actor=actor, context=context))


@router.get(BASE + "/diagnostics")
async def diagnostics(request: Request):
    _admit(request)
    return Response(json.dumps(await _call(spending.diagnostics), indent=2), media_type="application/json",
                    headers={"Cache-Control": "private, no-store", "Content-Disposition": 'attachment; filename="Lightwork-spending-diagnostics.json"'})


@router.post(BASE + "/export")
async def export(request: Request):
    _admit(request, mutation=True)
    return Response(await _call(spending.export_accounting), media_type="application/json",
                    headers={"Cache-Control": "private, no-store", "Content-Disposition": 'attachment; filename="Lightwork-provider-accounting.json"'})


@router.post(BASE + "/hold-review")
async def hold_review(request: Request, body: HoldIn):
    actor, context = _admit(request, mutation=True)
    return _json(await _call(spending.prepare_hold, body.provider, body.period, body.receipt, body.actual, body.evidence,
                            actor=actor, context=context, isolated=isolated(request.app)))


@router.post(BASE + "/import")
async def import_accounting(request: Request):
    actor, context = _admit(request, mutation=True)
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > spending.MAX_UPLOAD:
            raise HTTPException(413, "Choose an accounting copy file of 16 MB or less.")
        content.extend(chunk)
    return _json(await _call(spending.stage_import, bytes(content), actor=actor, context=context, isolated=isolated(request.app)))


@router.post(BASE + "/repair-review")
async def repair_review(request: Request, body: RepairIn):
    actor, context = _admit(request, mutation=True)
    return _json(await _call(spending.prepare_repair, body.imported, [row.model_dump() for row in body.totals], body.evidence,
                            actor=actor, context=context, isolated=isolated(request.app), receipts_complete=body.receipts_complete))


@router.post(BASE + "/apply")
async def apply(request: Request, body: ApplyIn):
    actor, context = _admit(request, mutation=True)
    return _json(await _call(spending.apply, body.review, actor=actor, context=context,
                            isolated=isolated(request.app), confirm=body.confirm))
