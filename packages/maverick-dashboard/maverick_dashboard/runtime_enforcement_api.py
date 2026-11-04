"""Current authorized readback of actual native safeguard activity."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, Response
from maverick import ai_governance_loop, ai_runtime_guardrails, model_risk_assurance
from maverick import runtime_enforcement_records as native
from starlette.concurrency import run_in_threadpool

from . import auth
from .draft_api import context_for

router = APIRouter(prefix="/assurance/runtime-enforcement", tags=["runtime-enforcement"])
LABELS = {"prepared": "Result not confirmed", "refused": "Action stopped before sending",
    "executed": "Connected service returned a result", "failed": "Connected service reported a problem",
    "accepted": "Connected service accepted it; completion is not confirmed",
    "indeterminate": "Outside result is unknown; check the connected service"}


def authority(request):
    from .app import require_page_visible

    with auth.fresh_configuration():
        auth.require_permission(request, "audit")
        auth.require_page_permission(request, "/security/governance")
        auth.require_suite(request, "it_grc")
        require_page_visible(request, "/security/governance")
        return context_for(request)


def _projection(row):
    binding = row["receipt"]["asset_binding"]
    asset = model_risk_assurance.get_observation(binding["asset_id"])
    name = (asset or {}).get("display_name") or "AI system name unavailable in this view"
    state = row["status"] if row["confirmed"] else "prepared"
    return {"id": row["id"], "system": name, "time": row["created_at"], "updated": row["updated_at"],
        "status": state, "meaning": LABELS[state], "checked_choice": row["receipt"]["decision"],
        "source_current": asset is not None and asset.get("revision") == binding["asset_revision"]
            and asset.get("version_digest") == binding["asset_version_digest"],
        "categories": row["receipt"]["categories"], "rules_checked": len(row["receipt"]["rule_ids"]),
        "controls_checked": len(row["receipt"]["control_ids"]),
        "evidence": {"asset_revision": binding["asset_revision"], "asset_digest": binding["asset_version_digest"],
            "policy_digest": row["receipt"]["policy_sha256"], "request_digest": row["request_sha256"],
            "receipt_revision": row["revision"], "activity_confirmed": row["confirmed"]}}


def catalog(request, offset=0):
    context = authority(request)
    try:
        rows = sorted(native.records(), key=lambda row: (row["created_at"], row["id"]), reverse=True)
        items = [_projection(row) for row in rows[offset:offset + 50]]
        runtime_enabled, loop_enabled = ai_runtime_guardrails.enabled(), ai_governance_loop.enabled()
    except Exception as exc:
        raise HTTPException(503, "Saved safeguard activity is unavailable. No action was repeated.") from exc
    if authority(request) != context:
        raise HTTPException(409, "Your account or workspace changed. Open the current safeguard activity again.")
    return {"context": context, "items": items, "total": len(rows), "offset": offset,
        "has_more": offset + len(items) < len(rows), "runtime_enabled": runtime_enabled, "loop_enabled": loop_enabled,
        "notice": "Only actions sent through Lightwork's governed connection are recorded here. Test results, previews and waiting approvals do not prove an action happened. Unknown results must be checked in the connected service before any new send."}


@router.get("")
async def list_activity(request: Request, response: Response, offset: int = Query(0, ge=0, le=native.MAX_RECORDS)):
    response.headers["Cache-Control"] = "no-store"
    return await run_in_threadpool(catalog, request, offset)


@router.get("/{identifier}")
async def read_original(request: Request, response: Response, identifier: str):
    import re

    context = authority(request)
    if re.fullmatch(r"RTE-[a-f0-9]{32}", identifier) is None:
        raise HTTPException(404, "This saved safeguard activity is unavailable.")
    response.headers["Cache-Control"] = "no-store"
    try:
        row = await run_in_threadpool(native.original, identifier)
    except native.EnforcementUnavailable as exc:
        raise HTTPException(503, "The saved safeguard activity could not be read. No action was repeated.") from exc
    if row is None:
        raise HTTPException(404, "No exact saved safeguard activity was found. This read sent nothing.")
    value = await run_in_threadpool(_projection, row)
    if authority(request) != context:
        raise HTTPException(409, "Your account or workspace changed. No action was repeated.")
    return {"context": context, "original": value}
