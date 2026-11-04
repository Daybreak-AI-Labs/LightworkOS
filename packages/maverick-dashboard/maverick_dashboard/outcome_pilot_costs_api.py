"""Financial-admin admission discovery, still bound to the pilot owner's context."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, Response
from maverick import ai_cost_roi
from maverick.paths import current_tenant_id_strict
from pydantic import Field

from . import outcome_pilot_costs as costs
from . import outcome_pilots as pilots
from . import outcome_pilots_api as pilot_api
from .auth import caller_principal, require_global_permission

router = APIRouter(tags=["outcome-pilot-costs"])
BASE = "/api/v1/outcome-pilots/{pilot_id}/provider-costs"


class ShareIn(pilot_api.StrictIn):
    case_id: str = Field(..., pattern=r"^[1-9][0-9]{0,2}$")
    basis_points: int = Field(..., ge=1, le=10000)
    source_version: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class AllocationIn(pilot_api.StrictIn):
    expected_revision: int = Field(..., ge=1)
    operation_id: str = Field(..., min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    observation_id: str = Field(..., pattern=r"^ACO-[0-9a-f]{32}$")
    billing_version: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    shares: list[ShareIn] = Field(..., max_length=100)
    note: str = Field(..., min_length=1, max_length=4000)
    confirm: bool = Field(...)


class CoverageIn(pilot_api.StrictIn):
    expected_revision: int = Field(..., ge=1)
    operation_id: str = Field(..., min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    coverage_version: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    currency: str = Field(..., pattern=r"^[A-Z]{3}$")
    note: str = Field(..., min_length=1, max_length=4000)
    confirm: bool


def require_billing(request):
    # Provider billing admissions can include every owner in this workspace.
    # Pilot ownership alone is deliberately insufficient for this discovery.
    require_global_permission(request, "admin")
    if not current_tenant_id_strict():
        raise HTTPException(403, "Select a named workspace before reading provider billing.")
    if not ai_cost_roi.enabled():
        raise HTTPException(403, "Enable AI cost and ROI in Settings before allocating admitted provider costs.")


async def report_for(request, record):
    try:
        require_billing(request)
    except HTTPException:
        return {"status": "unavailable", "reason": "Provider billing requires global administrator access and enabled AI cost and ROI."}
    try:
        return await pilot_api._call(costs.report, record, resolve=pilot_api._resolver(request))
    except HTTPException:
        return {"status": "unavailable", "reason": "Current provider receipt integrity or source access could not be verified. No provider cost total is available."}


@router.get(BASE)
async def catalogue(request: Request, response: Response, pilot_id: str,
                    offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100),
                    query: str = Query("", max_length=200)):
    context = pilot_api._context(request)
    require_billing(request)
    response.headers["Cache-Control"] = "private, no-store"
    await pilot_api._call(pilots.get, pilot_id, context)
    values = await pilot_api._call(costs.sources)
    terms = query.casefold().split()
    matches = [row for row in values.values() if all(term in " ".join(str(row[k]) for k in
               ("provider", "source_record_id", "source_account_id", "currency")).casefold() for term in terms)]
    matches.sort(key=lambda row: (row["period_start"], row["id"]))
    return {"items": matches[offset:offset + limit], "total": len(matches), "offset": offset,
            "next_offset": offset + limit if offset + limit < len(matches) else None, "context": context}


@router.put(BASE)
async def allocate(request: Request, response: Response, pilot_id: str, body: AllocationIn):
    context = pilot_api._context(request, mutation=True)
    require_billing(request)
    if body.confirm is not True:
        raise HTTPException(422, "Review the source, case shares and attribution before confirming.")
    response.headers["Cache-Control"] = "private, no-store"
    saved = await pilot_api._call(costs.allocate, pilot_id, body.model_dump(), context=context,
        actor=caller_principal(request) or "local:dashboard", resolve=pilot_api._resolver(request))
    return {"id": saved["id"], "revision": saved["revision"], "context": context}


@router.put(BASE + "/coverage")
async def confirm_coverage(request: Request, response: Response, pilot_id: str, body: CoverageIn):
    context = pilot_api._context(request, mutation=True)
    require_billing(request)
    if body.confirm is not True:
        raise HTTPException(422, "Confirm complete planned-case provider cost coverage before saving this review.")
    response.headers["Cache-Control"] = "private, no-store"
    saved = await pilot_api._call(costs.confirm_coverage, pilot_id, body.model_dump(), context=context,
        actor=caller_principal(request) or "local:dashboard", resolve=pilot_api._resolver(request))
    return {"id": saved["id"], "revision": saved["revision"], "context": context}
