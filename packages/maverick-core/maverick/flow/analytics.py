"""Per-flow run analytics: volume, success rate, duration percentiles, errors.

Lives in the engine package (not the dashboard) so every surface -- API, CLI,
MCP -- aggregates runs the same way, and so the status vocabulary comes from
:mod:`.runner`'s constants instead of being re-spelled: a new pause status is
then counted correctly here without anyone remembering this file exists.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from ..budget_tuner import percentile
from .run_state import (
    PAUSED_STATUSES,
    STATUS_BUDGET_LIMITED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_REJECTED,
)
from .store import FlowRun, list_run_metadata

_TOP_ERRORS = 3


def run_duration(run: FlowRun) -> float:
    """A run's wall-clock: the sum of its work nodes' measured seconds (the
    single definition of duration -- the run viewer and analytics must agree)."""
    total = 0.0
    for st in (run.nodes or {}).values():
        if isinstance(st, dict) and isinstance(st.get("seconds"), (int, float)):
            total += float(st["seconds"])
    return total


def aggregate(*, owner: str | None = None, limit: int = 500) -> dict:
    """Aggregate the most recent ``limit`` runs into per-flow analytics rows
    (sorted by run count): completion/failure/rejection counts, success rate
    over finished runs, p50/p95 completed-run duration, top error messages."""
    runs = list_run_metadata(owner=owner, limit=limit)
    by_flow: dict = defaultdict(lambda: {"runs": 0, "completed": 0, "failed": 0,
                                         "rejected": 0, "paused": 0,
                                         "durations": [], "errors": Counter()})
    for r in runs:
        agg = by_flow[r.flow_id]
        agg["runs"] += 1
        if r.status == STATUS_COMPLETED:
            agg["completed"] += 1
            agg["durations"].append(run_duration(r))
        elif r.status == STATUS_FAILED:
            agg["failed"] += 1
            if r.error:
                agg["errors"][str(r.error)[:160]] += 1
        elif r.status == STATUS_REJECTED:
            agg["rejected"] += 1
        elif r.status in PAUSED_STATUSES or r.status == STATUS_BUDGET_LIMITED:
            agg["paused"] += 1
    out = []
    for flow_id, agg in by_flow.items():
        finished = agg["completed"] + agg["failed"] + agg["rejected"]
        out.append({
            "flow_id": flow_id, "runs": agg["runs"],
            "completed": agg["completed"], "failed": agg["failed"],
            "rejected": agg["rejected"], "paused": agg["paused"],
            "success_rate": round(agg["completed"] / finished, 3) if finished else None,
            "p50_seconds": round(percentile(agg["durations"], 50), 3),
            "p95_seconds": round(percentile(agg["durations"], 95), 3),
            "top_errors": [{"error": e, "count": c}
                           for e, c in agg["errors"].most_common(_TOP_ERRORS)],
        })
    out.sort(key=lambda f: f["runs"], reverse=True)
    return {"flows": out, "run_window": len(runs)}
