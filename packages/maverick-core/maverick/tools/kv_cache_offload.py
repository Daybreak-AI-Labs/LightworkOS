"""KV-cache offload-to-disk planner.

Decide which KV-cache blocks stay resident in memory and which spill to disk
under a byte budget, using least-recently-used eviction. The caller supplies
the blocks, the current turn, and the memory budget; this keeps the most
recently used blocks that fit and offloads the rest, reporting bytes kept vs
offloaded. Deterministic and offline.

ops:
  - plan(blocks, current_turn, mem_budget_bytes)  — KEEP / OFFLOAD + byte split.

blocks: ``[{"id": str, "bytes": int, "last_used_turn": int}, ...]``. Keep order
is most-recently-used first (largest ``last_used_turn``); ties broken by id for
determinism. A block larger than the whole budget is offloaded.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _plan(blocks: list, current_turn: Any, mem_budget: Any) -> str:
    try:
        budget = int(mem_budget)
    except (TypeError, ValueError):
        return "ERROR: mem_budget_bytes (integer) is required"
    if budget < 0:
        return "ERROR: mem_budget_bytes must be >= 0"
    try:
        cur = int(current_turn)
    except (TypeError, ValueError):
        return "ERROR: current_turn (integer) is required"

    parsed: list[tuple[str, int, int]] = []
    for b in blocks:
        if not isinstance(b, dict):
            return "ERROR: each block must be an object {id, bytes, last_used_turn}"
        if "id" not in b:
            return "ERROR: each block needs an 'id'"
        bid = str(b["id"])
        try:
            nbytes = int(b.get("bytes"))
            last = int(b.get("last_used_turn"))
        except (TypeError, ValueError):
            return "ERROR: each block needs integer bytes and last_used_turn"
        if nbytes < 0:
            return "ERROR: block.bytes must be >= 0"
        parsed.append((bid, nbytes, last))

    # Most-recently-used first; recency relative to current_turn (smaller
    # gap = hotter). Ties by id for a stable plan.
    order = sorted(parsed, key=lambda x: (cur - x[2], x[0]))

    keep: list[str] = []
    offload: list[str] = []
    used = 0
    kept_bytes = 0
    off_bytes = 0
    for bid, nbytes, _last in order:
        if used + nbytes <= budget:
            keep.append(bid)
            used += nbytes
            kept_bytes += nbytes
        else:
            offload.append(bid)
            off_bytes += nbytes

    keep.sort()
    offload.sort()

    def _fmt(ids: list[str]) -> str:
        return "[" + ", ".join(ids) + "]" if ids else "[]"

    return (
        f"OK keep={len(keep)} offload={len(offload)} "
        f"budget={budget} used={kept_bytes}\n"
        f"  KEEP={_fmt(keep)} OFFLOAD={_fmt(offload)}\n"
        f"  bytes kept={kept_bytes} offloaded={off_bytes}"
    )


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "plan"):
        return f"ERROR: unknown op {args.get('op')!r}"
    blocks = args.get("blocks")
    if not isinstance(blocks, list):
        return "ERROR: blocks (list of {id, bytes, last_used_turn}) is required"
    if "current_turn" not in args:
        return "ERROR: current_turn (integer) is required"
    if "mem_budget_bytes" not in args:
        return "ERROR: mem_budget_bytes (integer) is required"
    return _plan(blocks, args.get("current_turn"), args.get("mem_budget_bytes"))


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["plan"]},
        "blocks": {
            "type": "array",
            "description": "KV-cache blocks: {id, bytes, last_used_turn}",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "bytes": {"type": "integer"},
                    "last_used_turn": {"type": "integer"},
                },
                "required": ["id", "bytes", "last_used_turn"],
            },
        },
        "current_turn": {"type": "integer"},
        "mem_budget_bytes": {"type": "integer", "description": "In-memory byte budget"},
    },
    "required": ["blocks", "current_turn", "mem_budget_bytes"],
}


def kv_cache_offload() -> Tool:
    return Tool(
        name="kv_cache_offload",
        description=(
            "KV-cache offload-to-disk planner. op=plan with 'blocks' "
            "({id, bytes, last_used_turn}), 'current_turn', and "
            "'mem_budget_bytes'; keeps the most-recently-used blocks that fit the "
            "budget (LRU) and offloads the rest, reporting bytes kept vs "
            "offloaded. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
