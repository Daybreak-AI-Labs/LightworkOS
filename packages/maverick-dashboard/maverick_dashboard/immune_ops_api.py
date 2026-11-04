"""Two more Safety monitoring (/immune) buttons for ``maverick immune``:

* ``POST /api/v1/immune/canaries/written`` -- place one reviewer test you
  wrote yourself: an approval with a planted mistake you describe (``maverick
  immune canary``). Workspace ``admin``, like planting tests modelled on real
  approvals. The planted mistake is kept private and never returned, so
  whoever reviews it can be measured fairly.
* ``POST /api/v1/immune/network/check`` -- find chains of assistants where
  private data could reach the outside (``maverick immune network``), for
  the installed assistants with or without shared team messaging and, as a
  what-if, with autonomy levels or data connectors switched on or off
  (``--levels`` / ``--grounding``), or for a set of assistants described in a
  file (``audit``, like the page). The what-if settings are handed to the
  check itself; nothing the running assistants read is changed.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_permission

router = APIRouter(prefix="/api/v1/immune", tags=["immune-operations"])

_MAX_GRAPH_BYTES = 512 * 1024
_MAX_AGENTS = 2000
_MAX_FINDINGS = 50


class WrittenCanaryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(min_length=1, max_length=200)
    detail: str = Field(min_length=1, max_length=4000)
    decision_class: str = Field(min_length=1, max_length=200)
    flaw: str = Field(min_length=1, max_length=1000)
    risk: Literal["low", "medium", "high"] = "medium"
    requested_by: str | None = Field(default=None, max_length=300)
    # Matches the kind of request imitated: a task's step can be undone for a
    # moment after a decision; a merge, settings change or agent access cannot.
    undoable: bool = True


class NetworkIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    shared_messaging: bool = False
    #: What if autonomy levels / data connectors were on (True) or off
    #: (False)? None keeps this installation's current setting.
    levels: bool | None = None
    grounding: bool | None = None
    #: A file describing assistants and how data flows between them.
    graph: str | None = Field(default=None, max_length=_MAX_GRAPH_BYTES)


def _world():
    from ._shared import _world as shared

    try:
        return shared()
    except Exception as exc:  # noqa: BLE001 -- plain message, no internals
        raise HTTPException(status_code=503, detail="Lightwork's records are not available right now.") from exc


def _record(request: Request, action: str, **payload: Any) -> None:
    from maverick.audit import AuditRefused, audit_event

    try:
        audit_event("immune_action", agent="dashboard", action=action,
                    actor=caller_principal(request) or "local", **payload)
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail=(
            "This could not be added to the activity log, so nothing was changed.")) from exc


@router.post("/canaries/written")
async def plant_written_canary(request: Request, body: WrittenCanaryIn) -> dict:
    require_permission(request, "admin")
    from maverick.immune import oversight

    if not oversight.canaries_enabled():
        raise HTTPException(status_code=409, detail="Reviewer tests are turned off. Turn them on first.")
    requested_by = None
    if body.requested_by:
        from .immune_actions_api import people_choices

        allowed = {p["value"] for p in await run_in_threadpool(people_choices)}
        if body.requested_by not in allowed:
            raise HTTPException(status_code=422, detail="Choose a person from the list.")
        requested_by = body.requested_by
    world = _world()
    # Recorded before the test approval exists; the mistake itself is never logged.
    await run_in_threadpool(_record, request, "plant_written_reviewer_test", risk=body.risk)
    try:
        await run_in_threadpool(lambda: oversight.seed_canary(
            world, action=body.action.strip(), detail=body.detail.strip(),
            decision_class=body.decision_class.strip(), flaw=body.flaw.strip(),
            risk=body.risk, requested_by=requested_by, undoable=body.undoable))
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail="Reviewer tests are turned off. Turn them on first.") from exc
    # The approval it hides in and the planted mistake stay private.
    return {"planted": 1, "message": "The test approval is in the approvals queue. Nobody is told it is a test."}


def _graph_from_file(text: str):
    from maverick.immune import network as n

    try:
        data = json.loads(text)
    except ValueError:
        raise HTTPException(status_code=422, detail="That file is not an assistant map.") from None
    agents = data.get("agents") if isinstance(data, dict) else None
    if not isinstance(agents, dict) or not agents or len(agents) > _MAX_AGENTS or not all(
            isinstance(v, list) for v in agents.values()):
        raise HTTPException(status_code=422, detail="That file is not an assistant map.")
    try:
        return n.load_graph(data)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=(
            "The map names data flows between assistants it does not list.")) from exc


def _network(body: NetworkIn) -> dict[str, Any]:
    from maverick.immune import network as n

    graph = (_graph_from_file(body.graph) if body.graph else
             n.roster_graph(swarm=body.shared_messaging, levels=body.levels, grounding=body.grounding))
    found = n.findings(graph)
    kinds = Counter(f.kind for f in found)
    chains = [{
        "kind": "Can read, change and send out" if f.kind == "trifecta" else "Can read and send out",
        "path": [p.replace("_", " ") for p in f.path],
        "reads_with": f.witness.get("sensitive", ("", ""))[1].replace("_", " "),
        "sends_with": f.witness.get("external", ("", ""))[1].replace("_", " "),
        "risk": {"low": "Low", "medium": "Medium", "high": "High"}.get(f.sink_risk, f.sink_risk.capitalize()),
    } for f in found[:_MAX_FINDINGS]]
    total = len(found)
    summary = (f"Checked {len(graph.agents)} assistant{'s' if len(graph.agents) != 1 else ''}. "
               + ("No chain lets private data reach the outside." if not total else
                  f"{total} chain{'s let' if total != 1 else ' lets'} private data reach the outside"
                  f" ({kinds.get('trifecta', 0)} can also change things)."))
    return {"assistants": len(graph.agents), "chains": chains, "total": total,
            "shown": len(chains), "summary": summary}


@router.post("/network/check")
async def network_check(request: Request, body: NetworkIn) -> dict:
    require_permission(request, "audit")
    if body.graph and len(body.graph.encode("utf-8")) > _MAX_GRAPH_BYTES:
        raise HTTPException(status_code=413, detail="That file is too large.")
    try:
        return await run_in_threadpool(_network, body)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 -- reported plainly
        raise HTTPException(status_code=503, detail="The check could not be completed right now.") from exc


__all__ = ["router"]
