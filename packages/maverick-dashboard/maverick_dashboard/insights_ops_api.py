"""The parts of two terminal reports that had no page yet.

* ``maverick proof`` (the workforce value report): the Savings page already
  shows its cost and savings figures; this adds the rest of the same report,
  ``maverick.workforce_value.compute`` -- whether recall got better across the
  recorded learning checkpoints, whether the activity record verifies intact,
  and the outside agents' results by vendor (``fleet_breakdown``). Read by
  anyone who can open Savings (``view``), for the current workspace.
* ``maverick charts``: /spend and /savings already chart spending and finished
  tasks; this adds the per-day finished/stopped task counts and how long each
  tool takes (``maverick.terminal_charts`` data and the live tool timing
  profile) to the Performance page, which is for global administrators.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission

router = APIRouter(prefix="/api/v1/insights")
asset_router = APIRouter()
_STATIC = Path(__file__).parent / "static"
_DAYS = (7, 14, 30, 90, 180, 365)


@asset_router.get("/static/lightwork-insights-ops.js", include_in_schema=False)
async def insights_ops_script() -> FileResponse:
    return FileResponse(_STATIC / "lightwork-insights-ops.js", media_type="application/javascript; charset=utf-8",
                        headers={"Cache-Control": "public, max-age=300"})


def _days(days: int) -> int:
    if days not in _DAYS:
        raise HTTPException(422, "Choose one of the listed time periods.")
    return days


def _value_report(days: int, owner=None) -> dict[str, Any]:
    from maverick import workforce_value

    from ._shared import _world
    report = workforce_value.compute(_world(), window_days=days, owner=owner)
    improvement = report.improvement
    checkpoints = len(report.coverage_trend)
    if not report.available:
        learning = report.unavailable_reason
    elif improvement is None:
        learning = ("Not enough learning checkpoints yet to show a trend. They are recorded each time Lightwork "
                    "reviews its past work.")
    elif improvement >= 0:
        learning = (f"Over {checkpoints} learning checkpoints, Lightwork's lessons came to cover {improvement} "
                    "more of its past mistakes.")
    else:
        learning = (f"Over {checkpoints} learning checkpoints, Lightwork's lessons cover {-improvement} fewer of "
                    "its past mistakes than before. Review recent learning changes.")
    chain = report.governance.get("chain_verifiable")
    record = ("The activity record is signed and checks out as unchanged." if chain else
              "The activity record isn't signed on this installation, so it can't be checked for changes."
              if chain is False else "The activity record could not be checked.")
    vendors = []
    for vendor, counts in sorted(workforce_value.fleet_breakdown().items()):
        vendors.append({"vendor": str(vendor)[:80], "delivered": int(counts.get("deliverables") or 0),
                        "failed": int(counts.get("failures") or 0)})
    return {"days": days, "learning": learning, "improvement": improvement, "checkpoints": checkpoints,
            "trend": [{"day": day, "covered": covered} for day, covered in report.coverage_trend][-60:],
            "record": record, "record_intact": chain, "vendors": vendors[:50]}


@router.get("/value-report")
async def value_report(request: Request, days: int = 90) -> dict:
    require_permission(request, "view")
    from .auth import goal_owner_filter
    return await run_in_threadpool(_value_report, _days(days), goal_owner_filter(request))


def _charts(days: int) -> dict[str, Any]:
    from maverick import terminal_charts, tool_latency

    from ._shared import _world
    rows = terminal_charts.goal_throughput(_world(), days=days)
    timing = [{"tool": str(r["tool"])[:120], "uses": int(r["count"]), "typical_ms": r["p50_ms"],
               "slow_ms": r["p95_ms"], "slowest_ms": r["max_ms"]} for r in tool_latency.report()[:25]]
    return {"days": days,
            "tasks": [{"day": day, "finished": done, "stopped": failed} for day, done, failed in rows],
            "tools": timing}


@router.get("/charts")
async def charts(request: Request, days: int = 7) -> dict:
    require_global_permission(request, "admin")
    return await run_in_threadpool(_charts, _days(days))
