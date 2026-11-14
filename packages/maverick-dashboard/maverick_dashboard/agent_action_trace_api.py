"""Read-only agent-action policy checks and traceability for the dashboard.

These were command-line only (``maverick governance check``, ``lineage`` and
``impact``). Nothing here writes: the policy check evaluates the active
organisation policy for one tool, lineage reads one task's recorded actions
and verifies the chain, and impact lists recorded actions that used a skill
or source. Lineage storage already resolves under the active workspace.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from .auth import assert_goal_access, can_access_goal, require_permission

router = APIRouter(
    prefix="/security/governance/agent-actions", tags=["governance-agent-actions"]
)

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+\-]{0,199}\Z")
_MAX_LINKS = 500
_MAX_HITS = 500


def _name(value: str, label: str) -> str:
    value = value.strip()
    if not _NAME.match(value):
        raise HTTPException(status_code=422, detail=f"{label} is not a recognised name")
    return value


def _chain_state(report: str) -> str:
    """Map the verifier's report to one closed keyword."""

    head = str(report).split(":", 1)[0].strip().upper()
    return head.lower() if head in {"VALID", "BROKEN", "MISSING", "UNAVAILABLE"} else "unavailable"


def _strings(value: Any) -> list[str]:
    return [str(item) for item in value][:50] if isinstance(value, list) else []


@router.get("/check")
async def check_action(
    request: Request,
    action: str = Query(min_length=1, max_length=200),
    risk: Literal["low", "medium", "high"] | None = Query(default=None),
) -> dict[str, object]:
    """What the active organisation policy would decide for ``action``."""

    require_permission(request, "view")
    selected = _name(action, "action")
    from maverick.governance import evaluate

    try:
        verdict = await run_in_threadpool(evaluate, selected, risk=risk)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="policy check is unavailable") from exc
    return {
        "action": selected,
        "risk": risk,
        "decision": verdict.decision.value,
        "reason": verdict.reason,
        "rule": verdict.rule,
    }


@router.get("/lineage/{goal_id}")
async def goal_lineage(request: Request, goal_id: int) -> dict[str, object]:
    """One task's recorded actions and whether the chain is intact."""

    require_permission(request, "view")
    if not 0 < goal_id < 2**63:
        raise HTTPException(status_code=422, detail="task number is out of range")
    from maverick import governed_actions

    from ._shared import _world

    goal = await run_in_threadpool(_world().get_goal, goal_id)
    if goal is None:
        raise HTTPException(status_code=404, detail="no such task")
    # The same owner check as the task itself: a task someone may not open
    # does not show its recorded actions or sources either.
    assert_goal_access(request, goal)

    def _read() -> tuple[list[dict], str]:
        return (
            governed_actions.load_lineage(goal_id),
            governed_actions.verify_lineage_file(goal_id),
        )

    try:
        links, report = await run_in_threadpool(_read)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="task history is unavailable") from exc
    return {
        "goal_id": goal_id,
        "chain": _chain_state(report),
        "count": len(links),
        "items": [
            {
                "action": str(link.get("action") or ""),
                "skills": _strings(link.get("skills")),
                "sources": _strings(link.get("sources")),
                "ts": link.get("ts") if isinstance(link.get("ts"), (int, float)) else None,
            }
            for link in links[:_MAX_LINKS]
        ],
    }


@router.get("/impact")
async def impact(
    request: Request,
    name: str = Query(min_length=1, max_length=200),
    kind: Literal["skill", "source", "any"] = Query(default="any"),
) -> dict[str, object]:
    """Recorded actions, across tasks, that used a skill or source."""

    require_permission(request, "view")
    selected = _name(name, "name")
    from maverick import governed_actions

    from ._shared import _world

    def _visible_hits() -> tuple[list[dict], int]:
        world = _world()
        allowed: dict[object, bool] = {}
        visible = []
        found = governed_actions.impact_of(selected, kind=kind)
        for hit in found:
            goal_id = hit.get("goal_id")
            if goal_id not in allowed:
                goal = world.get_goal(goal_id) if isinstance(goal_id, int) else None
                allowed[goal_id] = goal is not None and can_access_goal(request, goal)
            if allowed[goal_id]:
                visible.append(hit)
        # Only a count: a ledger's name is a task id the viewer may not see.
        return visible, len(getattr(found, "skipped_ledgers", ()))

    try:
        hits, unreadable = await run_in_threadpool(_visible_hits)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="impact search is unavailable") from exc
    return {
        "name": selected,
        "kind": kind,
        "count": len(hits),
        "unreadable_ledgers": unreadable,
        "complete": unreadable == 0,
        "items": [
            {
                "goal_id": hit.get("goal_id"),
                "action": str(hit.get("action") or ""),
                "via": hit.get("via"),
                "ts": hit.get("ts") if isinstance(hit.get("ts"), (int, float)) else None,
            }
            for hit in hits[:_MAX_HITS]
        ],
    }


__all__ = ["router"]
