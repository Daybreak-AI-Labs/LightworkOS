"""Spend report tool — cost analytics for the agent.

Reads recent episode rows from the world model and produces a
human-readable rollup the agent can use to:

  - Tell the user how much a session has cost so far.
  - Decide whether to escalate to a more expensive model (e.g. "you
    have $0.50 of $5 budget left; staying on Sonnet").
  - Surface unusual cost spikes ("episode 47 cost 3× the median —
    likely an unbounded tool-call loop").

ops:
  - recent(limit, since_hours)   — table of recent episodes
  - by_role()                    — total $ per role (orchestrator vs proposer ...)
  - anomalies()                  — episodes more than 3× the median cost
  - total()                      — lifetime + 24h + 1h totals
"""
from __future__ import annotations

import logging
import statistics
import time
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_SPEND_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["recent", "by_role", "anomalies", "total"],
        },
        "limit": {"type": "integer"},
        "since_hours": {"type": "number"},
    },
    "required": ["op"],
}


def _world():
    from ..world_model import open_world
    return open_world()


def _episodes(limit: int = 200) -> list[dict]:
    w = _world()
    try:
        return list(w.list_episodes(limit=limit) or [])
    except Exception as e:
        log.warning("spend_report: cannot list episodes: %s", e)
        return []
    finally:
        from ..world_model import close_world_if_owned
        close_world_if_owned(w)


def _cost(ep) -> float:
    """Tolerate dataclasses, dicts, namedtuples — pick whichever shape ships."""
    try:
        return float(getattr(ep, "cost_dollars", 0.0) or 0.0)
    except Exception:
        pass
    try:
        return float(ep["cost_dollars"] or 0.0)
    except Exception:
        return 0.0


def _ts(ep) -> float:
    # WorldModel.list_episodes() returns EpisodeSpend dataclasses whose time
    # fields are ended_at / started_at -- NOT finished_at/created_at/ts. Probe
    # the real fields first (else every episode's timestamp read as 0.0, so any
    # time-window filtering / ordering in the report silently broke).
    for attr in ("ended_at", "started_at", "finished_at", "created_at", "ts"):
        try:
            v = getattr(ep, attr, None)
            if v:
                return float(v)
        except Exception:
            continue
    try:
        return float(
            ep.get("ended_at") or ep.get("started_at")
            or ep.get("finished_at") or ep.get("created_at") or 0
        )
    except Exception:
        return 0.0


def _role(ep) -> str:
    return (
        getattr(ep, "role", None)
        or (ep.get("role") if isinstance(ep, dict) else None)
        or "?"
    )


def _ep_id(ep) -> Any:
    return (
        getattr(ep, "id", None)
        or (ep.get("id") if isinstance(ep, dict) else None)
        or "?"
    )


def _op_recent(limit: int, since_hours: float) -> str:
    eps = _episodes(max(1, min(limit, 200)))
    if since_hours and since_hours > 0:
        cutoff = time.time() - since_hours * 3600
        eps = [e for e in eps if _ts(e) >= cutoff]
    if not eps:
        return "no episodes recorded"
    rows = [f"{'id':>6}  {'role':>14}  {'$':>8}  age"]
    now = time.time()
    for ep in eps[:limit]:
        age = now - _ts(ep)
        rows.append(
            f"{_ep_id(ep)!s:>6}  {_role(ep):>14}  "
            f"${_cost(ep):>7.4f}  {age/60:>6.1f} min ago"
        )
    return "\n".join(rows)


def _op_by_role() -> str:
    eps = _episodes(500)
    if not eps:
        return "no episodes recorded"
    totals: dict[str, float] = {}
    counts: dict[str, int] = {}
    for ep in eps:
        r = _role(ep)
        totals[r] = totals.get(r, 0.0) + _cost(ep)
        counts[r] = counts.get(r, 0) + 1
    rows = [f"{'role':>16}  {'total $':>10}  {'avg $':>10}  count"]
    for r in sorted(totals, key=lambda k: -totals[k]):
        avg = totals[r] / counts[r] if counts[r] else 0.0
        rows.append(f"{r:>16}  ${totals[r]:>9.4f}  ${avg:>9.4f}  {counts[r]}")
    return "\n".join(rows)


def _op_anomalies() -> str:
    eps = _episodes(500)
    costs = [_cost(e) for e in eps if _cost(e) > 0]
    if len(costs) < 5:
        return "not enough data (need >= 5 episodes with non-zero cost)"
    median = statistics.median(costs)
    threshold = max(median * 3, 0.01)
    anomalies = [e for e in eps if _cost(e) >= threshold]
    if not anomalies:
        return f"no anomalies (median cost ${median:.4f}, threshold ${threshold:.4f})"
    rows = [f"median ${median:.4f} — threshold ${threshold:.4f} (3× median)"]
    for ep in anomalies[:20]:
        rows.append(
            f"  ep {_ep_id(ep)} role={_role(ep)} "
            f"cost=${_cost(ep):.4f}  ({_cost(ep)/median:.1f}× median)"
        )
    return "\n".join(rows)


def _op_total() -> str:
    eps = _episodes(2000)
    if not eps:
        return "no episodes recorded"
    now = time.time()
    total = sum(_cost(e) for e in eps)
    last_24h = sum(_cost(e) for e in eps if now - _ts(e) <= 86400)
    last_1h = sum(_cost(e) for e in eps if now - _ts(e) <= 3600)
    return (
        f"lifetime:  ${total:.4f}  ({len(eps)} episodes)\n"
        f"last 24h:  ${last_24h:.4f}\n"
        f"last 1h:   ${last_1h:.4f}"
    )


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        if op == "recent":
            return _op_recent(
                int(args.get("limit") or 25),
                float(args.get("since_hours") or 0),
            )
        if op == "by_role":
            return _op_by_role()
        if op == "anomalies":
            return _op_anomalies()
        if op == "total":
            return _op_total()
    except Exception as e:
        return f"ERROR: spend_report failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def spend_report() -> Tool:
    return Tool(
        name="spend_report",
        description=(
            "Cost analytics over recent episodes. ops: recent "
            "(limit + since_hours), by_role (total + avg per role), "
            "anomalies (episodes >= 3× median cost), total "
            "(lifetime / 24h / 1h rollup). Use to decide when to "
            "escalate or to flag runaway loops."
        ),
        input_schema=_SPEND_SCHEMA,
        fn=_run,
    )
