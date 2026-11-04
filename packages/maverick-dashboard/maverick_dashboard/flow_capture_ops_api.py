"""Suggested data descriptions for keeping a flow run as a learning example.

The flow run page enrolls, reviews and grants learning examples through the
existing ``/api/v1/flows/{id}/runs/{run}/episode-capture*`` routes. Enrolling
needs complete descriptions of the run's inputs and each action's arguments
and result; this route returns the enrollment facts from the existing
preparation step (same permission, owner, workspace and pause checks) plus a
suggestion from :func:`maverick.flow.capture_schema.suggest_contract`, which
the page shows as plain editable fields. Read-only: nothing is enrolled here.
"""
from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter(tags=["flow-action-episodes"])
MAX_EARLIER = 20


@router.get("/api/v1/flows/{flow_id}/runs/{run_id}/episode-capture/suggestion")
def capture_suggestion(request: Request, flow_id: str, run_id: str):
    from maverick.flow import store
    from maverick.flow.capture_schema import suggest_contract

    from .api_flow_action_episodes import _call, _enrollment_info, _response, _service

    prepared = _call(lambda: _enrollment_info(request, flow_id[:256], run_id[:256]))
    service, ctx = _call(lambda: _service(request, flow_id[:256]))

    def work():
        run = store.load_run(run_id, owner=ctx.resource_owner, flow_id=flow_id)
        pinned = store.load_flow_snapshot(run.definition_digest)
        earlier, prior = [], None
        for meta in store.list_run_metadata(flow_id=flow_id, owner=ctx.resource_owner, limit=MAX_EARLIER):
            if meta.run_id == run_id:
                continue
            if prior is None:
                try:
                    detail = service.get(ctx, flow_id, meta.run_id, detail=True)
                    prior = (detail.get("evidence") or {}).get("contract")
                except Exception:  # no example recorded for that run
                    prior = None
            if meta.status == "completed" and len(earlier) < 5 and not meta.dry_run:
                full = store.load_run(meta.run_id, owner=ctx.resource_owner, flow_id=flow_id)
                if full is not None:
                    earlier.append(full)
        return suggest_contract(pinned, run, allowed_tools=prepared["allowed_tools"],
                                prior_contract=prior, earlier_runs=earlier)

    suggestion = _call(work)
    return _response({**prepared, "suggestion": suggestion, "max_days": 7})
