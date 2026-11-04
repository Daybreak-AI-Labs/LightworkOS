"""Latency heatmap tool.

Render a text heatmap of latency percentiles per bucket (a bucket = a tool name
or a time slot). Each cell is shaded with a unicode block (``░▒▓█``) scaled to
the cell's magnitude across the whole matrix, so hot spots pop out at a glance.
Deterministic and offline: percentiles use the nearest-rank method; shading is a
fixed linear bucketing of value into the four block glyphs.

ops:
  - render(samples[, percentiles])  — samples: list of {bucket, ms}.
"""
from __future__ import annotations

import math
from typing import Any

from . import Tool

_BLOCKS = " ░▒▓█"  # index 0 = empty cell (no data), 1..4 = increasing heat
_DEFAULT_PCTS = (50.0, 90.0, 99.0)


def _nearest_rank(sorted_vals: list[float], p: float) -> float:
    n = len(sorted_vals)
    rank = max(1, min(math.ceil((p / 100.0) * n), n))
    return sorted_vals[rank - 1]


def _label(p: float) -> str:
    return f"p{p:g}".replace(".", "")


def _shade(value: float, lo: float, hi: float) -> str:
    """Map value in [lo, hi] to one of the 4 heat blocks (1..4)."""
    if hi <= lo:
        return _BLOCKS[4]
    frac = (value - lo) / (hi - lo)
    idx = 1 + min(3, max(0, int(frac * 4 - 1e-9)))
    return _BLOCKS[idx]


def _render(samples: list, pcts: tuple[float, ...]) -> str:
    grouped: dict[str, list[float]] = {}
    for s in samples:
        if not isinstance(s, dict):
            continue
        bucket = str(s.get("bucket", "")) or "<none>"
        try:
            ms = float(s.get("ms"))
        except (TypeError, ValueError):
            continue
        grouped.setdefault(bucket, []).append(ms)

    if not grouped:
        return "ERROR: no valid samples ({bucket, ms})"

    for vals in grouped.values():
        vals.sort()

    buckets = sorted(grouped)
    matrix: dict[str, dict[str, float]] = {
        b: {_label(p): _nearest_rank(grouped[b], p) for p in pcts}
        for b in buckets
    }
    all_vals = [v for row in matrix.values() for v in row.values()]
    lo, hi = min(all_vals), max(all_vals)

    col_labels = [_label(p) for p in pcts]
    width = max([len(b) for b in buckets] + [6])
    header = "bucket".ljust(width) + " | " + "  ".join(
        f"{c:>8}" for c in col_labels
    )
    lines = [header, "-" * len(header)]
    for b in buckets:
        cells = []
        for c in col_labels:
            v = matrix[b][c]
            cells.append(f"{_shade(v, lo, hi)} {v:>6g}")
        lines.append(b.ljust(width) + " | " + "  ".join(cells))
    lines.append(f"legend: {_BLOCKS[1]}<{_BLOCKS[2]}<{_BLOCKS[3]}<{_BLOCKS[4]}  "
                 f"range {lo:g}..{hi:g}ms")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "render"):
        return f"ERROR: unknown op {args.get('op')!r}"
    samples = args.get("samples")
    if not isinstance(samples, list) or not samples:
        return "ERROR: samples (non-empty list of {bucket, ms}) is required"
    raw_pcts = args.get("percentiles")
    if raw_pcts is None:
        pcts: tuple[float, ...] = _DEFAULT_PCTS
    else:
        if not isinstance(raw_pcts, list) or not raw_pcts:
            return "ERROR: percentiles must be a non-empty list of numbers"
        try:
            pcts = tuple(float(p) for p in raw_pcts)
        except (TypeError, ValueError):
            return "ERROR: percentiles must all be numbers"
        if any(not 0 < p <= 100 for p in pcts):
            return "ERROR: percentiles must be in (0, 100]"
    return _render(samples, pcts)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["render"]},
        "samples": {
            "type": "array",
            "description": "latency samples; each {bucket, ms}",
            "items": {
                "type": "object",
                "properties": {
                    "bucket": {"type": "string", "description": "tool name or time slot"},
                    "ms": {"type": "number"},
                },
                "required": ["bucket", "ms"],
            },
        },
        "percentiles": {
            "type": "array",
            "description": "percentiles per column (default 50/90/99)",
            "items": {"type": "number"},
        },
    },
    "required": ["samples"],
}


def latency_heatmap() -> Tool:
    return Tool(
        name="latency_heatmap",
        description=(
            "Render a text latency heatmap. op=render with 'samples' (each "
            "{bucket, ms}) and optional 'percentiles' (default 50/90/99). "
            "Builds a percentile-per-bucket matrix with unicode-block shaded "
            "cells (░▒▓█ by magnitude). Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
