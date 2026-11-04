"""WAL contention audit.

A write-ahead log serialises commits, so p99 write latency should rise roughly
linearly with the number of concurrent writers. Where it rises *superlinearly*,
the WAL is the bottleneck and adding writers only hurts. Given p50/p99 latency
samples grouped by writer count, this flags the superlinear knees and recommends
a max-writers ceiling. Deterministic and offline.

Method: sort the buckets by writer count. Linear scaling predicts
``p99 ~ p99(baseline) * writers / writers(baseline)`` using the lowest writer
count as the baseline. A bucket is SUPERLINEAR when its observed p99 exceeds the
linear prediction by more than ``tolerance`` (default 25%). The recommended
ceiling is the largest writer count still scaling within tolerance (the last
good bucket before the first knee).

ops:
  - analyze(buckets, [tolerance])  — per-bucket OK/SUPERLINEAR + max-writers.

Buckets: ``[{"writers", "p50_ms", "p99_ms"}]``.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _analyze(buckets: list, tolerance: float) -> str:
    parsed: list[tuple[int, float, float]] = []
    for b in buckets:
        if not isinstance(b, dict):
            return "ERROR: each bucket must be an object"
        try:
            writers = int(b.get("writers"))
            p50 = float(b.get("p50_ms"))
            p99 = float(b.get("p99_ms"))
        except (TypeError, ValueError, OverflowError):
            return "ERROR: each bucket needs writers, p50_ms, p99_ms"
        if writers <= 0:
            return "ERROR: writers must be > 0"
        parsed.append((writers, p50, p99))

    parsed.sort(key=lambda x: x[0])
    seen = {w for w, _, _ in parsed}
    if len(seen) != len(parsed):
        return "ERROR: duplicate writer counts"

    base_w, _base_p50, base_p99 = parsed[0]
    lines: list[str] = []
    ceiling = base_w
    knee_found = False
    for writers, _p50, p99 in parsed:
        predicted = base_p99 * (writers / base_w)
        # Excess over the linear prediction, as a fraction.
        excess = (p99 - predicted) / predicted if predicted > 0 else 0.0
        superlinear = excess > tolerance
        if superlinear:
            tag = f"SUPERLINEAR p99={p99:g}ms vs linear~{predicted:g}ms (+{excess * 100:.0f}%)"
            if not knee_found:
                knee_found = True
        else:
            tag = f"OK p99={p99:g}ms vs linear~{predicted:g}ms"
            if not knee_found:
                ceiling = writers
        lines.append(f"  writers={writers}: {tag}")

    verdict = "DEGRADES" if knee_found else "OK"
    head = (
        f"{verdict} max_writers={ceiling} "
        f"(baseline writers={base_w} p99={base_p99:g}ms, tolerance={tolerance * 100:.0f}%)"
    )
    return head + "\n" + "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "analyze"):
        return f"ERROR: unknown op {args.get('op')!r}"
    buckets = args.get("buckets")
    if not isinstance(buckets, list) or not buckets:
        return "ERROR: buckets (non-empty list of {writers, p50_ms, p99_ms}) is required"
    tolerance = args.get("tolerance", 0.25)
    try:
        tolerance = float(tolerance)
    except (TypeError, ValueError):
        return "ERROR: tolerance must be a number"
    if tolerance < 0:
        return "ERROR: tolerance must be >= 0"
    return _analyze(buckets, tolerance)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["analyze"]},
        "buckets": {
            "type": "array",
            "description": "Latency by writer count: {writers, p50_ms, p99_ms}",
            "items": {
                "type": "object",
                "properties": {
                    "writers": {"type": "integer"},
                    "p50_ms": {"type": "number"},
                    "p99_ms": {"type": "number"},
                },
                "required": ["writers", "p50_ms", "p99_ms"],
            },
        },
        "tolerance": {
            "type": "number",
            "description": "Allowed p99 excess over the linear prediction (default 0.25)",
        },
    },
    "required": ["buckets"],
}


def wal_contention() -> Tool:
    return Tool(
        name="wal_contention",
        description=(
            "WAL contention audit. op=analyze with 'buckets' ({writers, p50_ms, "
            "p99_ms}) and optional 'tolerance' (default 0.25). Uses the lowest "
            "writer count as a linear baseline and flags writer counts whose p99 "
            "degrades superlinearly; recommends a max-writers ceiling (the last "
            "bucket scaling within tolerance). Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
