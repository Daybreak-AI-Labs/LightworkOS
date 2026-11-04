"""Tiered storage planner.

Partition a record set into a HOT tier (recently accessed, kept in fast row
storage like SQLite) and a COLD tier (idle, archived to columnar parquet). The
caller supplies the records and a retention policy; this resolves which records
migrate to cold and reports per-tier counts and byte totals. Deterministic and
offline: a record is COLD when it has not been accessed within ``hot_days``.

An optional ``max_hot_mb`` caps the hot tier: once HOT exceeds the cap, the
least-recently-accessed (largest ``last_access_days`` first) hot records spill
to COLD until the cap is met — so the hot store stays inside its budget.

ops:
  - plan(records, policy)  — HOT/COLD counts, bytes per tier, ids to migrate.

Records: ``[{"id", "last_access_days", "size_kb"}]``.
Policy:  ``{"hot_days", "max_hot_mb"?}``.
"""
from __future__ import annotations

import math
from typing import Any

from . import Tool


def _plan(records: list, policy: dict) -> str:
    try:
        hot_days = float(policy.get("hot_days"))
    except (TypeError, ValueError):
        return "ERROR: policy.hot_days (number) is required"
    if not math.isfinite(hot_days) or hot_days < 0:
        return "ERROR: policy.hot_days must be a finite number >= 0"

    max_hot_mb = policy.get("max_hot_mb")
    if max_hot_mb is not None:
        try:
            max_hot_mb = float(max_hot_mb)
        except (TypeError, ValueError):
            return "ERROR: policy.max_hot_mb must be a number"
        if not math.isfinite(max_hot_mb) or max_hot_mb < 0:
            return "ERROR: policy.max_hot_mb must be a finite number >= 0"

    parsed: list[tuple[str, float, float]] = []
    for r in records:
        if not isinstance(r, dict):
            return "ERROR: each record must be an object"
        rid = r.get("id")
        if rid is None:
            return "ERROR: each record needs an 'id'"
        try:
            age = float(r.get("last_access_days"))
            size = float(r.get("size_kb"))
        except (TypeError, ValueError):
            return "ERROR: each record needs numeric last_access_days and size_kb"
        if not math.isfinite(age) or not math.isfinite(size):
            return "ERROR: each record needs finite last_access_days and size_kb"
        if size < 0:
            return "ERROR: each record size_kb must be >= 0"
        parsed.append((str(rid), age, size))

    # Recency split: COLD if idle longer than the hot window.
    hot: list[tuple[str, float, float]] = []
    cold: list[tuple[str, float, float]] = []
    for rid, age, size in parsed:
        (cold if age > hot_days else hot).append((rid, age, size))

    # Capacity spill: evict coldest (largest last_access_days, then larger size,
    # then id) from HOT until under the byte cap. Deterministic ordering.
    if max_hot_mb is not None:
        cap_kb = max_hot_mb * 1024.0
        hot.sort(key=lambda x: (-x[1], -x[2], x[0]))  # coldest-first
        hot_kb = sum(s for _, _, s in hot)
        while hot and hot_kb > cap_kb:
            rid, age, size = hot.pop(0)
            cold.append((rid, age, size))
            hot_kb -= size

    hot_byte_total = sum(s for _, _, s in hot) * 1024
    cold_byte_total = sum(s for _, _, s in cold) * 1024
    if not math.isfinite(hot_byte_total) or not math.isfinite(cold_byte_total):
        return "ERROR: total size overflows; size_kb values are too large"
    hot_bytes = int(round(hot_byte_total))
    cold_bytes = int(round(cold_byte_total))
    migrate = sorted(rid for rid, _, _ in cold)
    shown = ", ".join(migrate) if migrate else "(none)"
    return (
        f"OK hot_days={hot_days:g} "
        f"HOT={len(hot)} ({hot_bytes} bytes) "
        f"COLD={len(cold)} ({cold_bytes} bytes)\n"
        f"  migrate_to_cold: [{shown}]"
    )


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "plan"):
        return f"ERROR: unknown op {args.get('op')!r}"
    records = args.get("records")
    if not isinstance(records, list):
        return "ERROR: records (list of {id, last_access_days, size_kb}) is required"
    policy = args.get("policy")
    if not isinstance(policy, dict):
        return "ERROR: policy ({hot_days, max_hot_mb?}) is required"
    return _plan(records, policy)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["plan"]},
        "records": {
            "type": "array",
            "description": "Records to tier: {id, last_access_days, size_kb}",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": ["string", "number"]},
                    "last_access_days": {"type": "number"},
                    "size_kb": {"type": "number"},
                },
                "required": ["id", "last_access_days", "size_kb"],
            },
        },
        "policy": {
            "type": "object",
            "description": "Retention policy: {hot_days, max_hot_mb?}",
            "properties": {
                "hot_days": {"type": "number", "description": "Idle days before a record goes cold"},
                "max_hot_mb": {"type": "number", "description": "Optional hot-tier byte cap (MB)"},
            },
            "required": ["hot_days"],
        },
    },
    "required": ["records", "policy"],
}


def tiered_storage() -> Tool:
    return Tool(
        name="tiered_storage",
        description=(
            "Tiered storage planner (hot SQLite + cold parquet). op=plan with "
            "'records' ({id, last_access_days, size_kb}) and 'policy' ({hot_days, "
            "max_hot_mb?}). Records idle longer than hot_days go COLD; an optional "
            "max_hot_mb cap spills the least-recently-accessed hot records to cold. "
            "Returns per-tier counts, bytes, and the ids to migrate to cold. "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
