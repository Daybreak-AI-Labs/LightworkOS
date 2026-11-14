"""Multi-agent fairness scheduler tool.

Allocates a fixed number of execution slots across competing agents by weighted
fair share, using the largest-remainder (Hamilton) method, and never hands an
agent more slots than it has pending (queued) tasks. Slots freed by that cap are
redistributed to other still-wanting agents. Deterministic and offline.

ops:
  - schedule(agents, slots)  — returns the per-agent allocation map and totals.

``agents``: list of {id, weight?, pending}. ``weight`` defaults to 1.
"""
from __future__ import annotations

import math
from typing import Any

from . import Tool


def _allocate(agents: list[dict[str, Any]], slots: int) -> dict[str, int]:
    """Weighted largest-remainder (Hamilton) allocation, capped by pending.

    Re-apportioned in rounds: the Hamilton method distributes the still-free
    slots across agents that still have headroom (alloc < pending, weight > 0).
    A cap hit in one round frees nothing in that round but removes the agent
    from the next round's pool, so the leftover flows to other wanting agents.
    Each round strictly increases the placed total or exhausts headroom, so the
    loop terminates.
    """
    alloc: dict[str, int] = {a["id"]: 0 for a in agents}
    while True:
        placed = sum(alloc.values())
        remaining = slots - placed
        if remaining <= 0:
            break
        active = [
            a for a in agents
            if alloc[a["id"]] < a["pending"] and a["weight"] > 0
        ]
        if not active:
            break
        total_weight = sum(a["weight"] for a in active)
        # Floor of each agent's ideal share, never above its headroom.
        quotas: list[tuple[float, float, str]] = []
        for a in active:
            aid = a["id"]
            ideal = remaining * (a["weight"] / total_weight)
            headroom = a["pending"] - alloc[aid]
            base = min(int(ideal), headroom)
            alloc[aid] += base
            # Remainder (for the largest-remainder tie-break) only matters for
            # agents that still have headroom after the floor pass.
            if alloc[aid] < a["pending"]:
                quotas.append((ideal - int(ideal), a["weight"], aid))
        leftover = slots - sum(alloc.values())
        if leftover <= 0:
            break
        # Largest-remainder: award single slots to the highest fractional
        # remainders (ties: higher weight, then id) among agents with headroom.
        quotas.sort(key=lambda t: (-t[0], -t[1], t[2]))
        progressed = False
        for _frac, _w, aid in quotas:
            if leftover <= 0:
                break
            alloc[aid] += 1
            leftover -= 1
            progressed = True
        if not progressed:
            # No agent had headroom for the leftover; nothing more to place.
            break
    return alloc


def _schedule(agents_in: list[Any], slots: int) -> str:
    agents: list[dict[str, Any]] = []
    seen: set[str] = set()
    for a in agents_in:
        if not isinstance(a, dict):
            return "ERROR: each agent must be an object {id, weight?, pending}"
        aid = a.get("id")
        if aid is None or str(aid).strip() == "":
            return "ERROR: each agent needs a non-empty 'id'"
        aid = str(aid)
        if aid in seen:
            return f"ERROR: duplicate agent id {aid!r}"
        seen.add(aid)
        try:
            pending = int(a.get("pending"))
        except (TypeError, ValueError, OverflowError):
            return f"ERROR: agent {aid!r} pending must be an integer"
        if pending < 0 or pending > _MAX_COUNT:
            return f"ERROR: agent {aid!r} pending must be between 0 and {_MAX_COUNT}"
        try:
            weight = float(a.get("weight", 1))
        except (TypeError, ValueError):
            return f"ERROR: agent {aid!r} weight must be a number"
        if not math.isfinite(weight):
            return f"ERROR: agent {aid!r} weight must be a finite number"
        if weight < 0:
            return f"ERROR: agent {aid!r} weight must be >= 0"
        agents.append({"id": aid, "weight": weight, "pending": pending})
    # Finite weights can still sum to infinity (two of 1e308); every ideal
    # share is then 0 and the allocator places one slot per agent per round.
    if not math.isfinite(sum(a["weight"] for a in agents)):
        return "ERROR: the sum of the weights must be a finite number"

    alloc = _allocate(agents, slots)
    total_alloc = sum(alloc.values())
    total_pending = sum(a["pending"] for a in agents)
    lines = [
        f"OK: allocated {total_alloc}/{slots} slot(s) across "
        f"{len(agents)} agent(s) (total pending {total_pending})"
    ]
    for a in agents:
        aid = a["id"]
        lines.append(
            f"{aid}: {alloc[aid]} (weight={_fmt(a['weight'])}, "
            f"pending={a['pending']})"
        )
    if total_alloc < slots:
        lines.append(
            f"note: {slots - total_alloc} slot(s) unallocated "
            f"(pending demand exhausted)"
        )
    return "\n".join(lines)


# Counts above 2**53 are not exact as floats, and the shares are floats.
_MAX_COUNT = 2**53


def _fmt(w: float) -> str:
    return str(int(w)) if w == int(w) else str(w)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "schedule"):
        return f"ERROR: unknown op {args.get('op')!r} (expected schedule)"
    agents = args.get("agents")
    if not isinstance(agents, list) or not agents:
        return "ERROR: agents (non-empty array of {id, weight?, pending}) is required"
    try:
        slots = int(args.get("slots"))
    except (TypeError, ValueError, OverflowError):
        return "ERROR: slots (integer) is required"
    if slots < 0 or slots > _MAX_COUNT:
        return f"ERROR: slots must be between 0 and {_MAX_COUNT}"
    return _schedule(agents, slots)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["schedule"]},
        "agents": {
            "type": "array",
            "description": "competing agents; each {id, weight?, pending}",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "weight": {"type": "number"},
                    "pending": {"type": "integer"},
                },
                "required": ["id", "pending"],
            },
        },
        "slots": {"type": "integer", "description": "number of slots to allocate"},
    },
    "required": ["agents", "slots"],
}


def fairness_scheduler() -> Tool:
    return Tool(
        name="fairness_scheduler",
        description=(
            "Multi-agent fairness scheduler. op=schedule with 'agents' (each "
            "{id, weight?, pending}) and 'slots' allocates slots by weighted "
            "fair share via the largest-remainder (Hamilton) method, never "
            "exceeding an agent's pending count; freed slots are redistributed. "
            "Returns the allocation map. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
