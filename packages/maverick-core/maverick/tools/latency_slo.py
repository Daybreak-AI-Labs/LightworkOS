"""Reliability SLO / tail-latency calculator.

Summarise a batch of latency samples into the percentiles operators actually
gate on (p50/p90/p95/p99/p999) and judge them against an SLO target. Deterministic
and offline: percentiles use the nearest-rank method over the sorted samples
(rank = ceil(p/100 * N), 1-indexed), and the verdict compares the target
percentile's value to the threshold.

ops:
  - report(samples, target)  — target: {p, threshold_ms}; PASS/FAIL + percentiles.
"""
from __future__ import annotations

import math
import statistics
from typing import Any

from . import Tool

_REPORT_PCTS = (50.0, 90.0, 95.0, 99.0, 99.9)


def _nearest_rank(sorted_samples: list[float], p: float) -> float:
    """Nearest-rank percentile: rank = ceil(p/100 * N), clamped to [1, N]."""
    n = len(sorted_samples)
    rank = math.ceil((p / 100.0) * n)
    rank = max(1, min(rank, n))
    return sorted_samples[rank - 1]


def _label(p: float) -> str:
    return f"p{p:g}".replace(".", "")  # 99.9 -> p999, 50 -> p50


def _report(samples: list, target: dict) -> str:
    try:
        vals = sorted(float(s) for s in samples)
    except (TypeError, ValueError):
        return "ERROR: samples must all be numbers"

    try:
        p = float(target.get("p"))
        threshold = float(target.get("threshold_ms"))
    except (TypeError, ValueError):
        return "ERROR: target needs numeric 'p' and 'threshold_ms'"
    if not 0 < p <= 100:
        return "ERROR: target.p must be in (0, 100]"

    pcts = {_label(x): _nearest_rank(vals, x) for x in _REPORT_PCTS}
    mean = statistics.fmean(vals)
    actual = _nearest_rank(vals, p)
    verdict = "PASS" if actual <= threshold else "FAIL"

    pct_line = "  ".join(f"{k}={v:g}ms" for k, v in pcts.items())
    return (f"{verdict} {_label(p)}={actual:g}ms vs threshold {threshold:g}ms "
            f"(n={len(vals)})\n"
            f"  {pct_line}  mean={mean:.2f}ms")


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "report"):
        return f"ERROR: unknown op {args.get('op')!r}"
    samples = args.get("samples")
    if not isinstance(samples, list) or not samples:
        return "ERROR: samples (non-empty list of latencies in ms) is required"
    target = args.get("target")
    if not isinstance(target, dict):
        return "ERROR: target ({p, threshold_ms}) is required"
    return _report(samples, target)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["report"]},
        "samples": {
            "type": "array",
            "description": "Latency samples in milliseconds",
            "items": {"type": "number"},
        },
        "target": {
            "type": "object",
            "description": "SLO target: {p (percentile), threshold_ms}",
            "properties": {
                "p": {"type": "number", "description": "Percentile to gate on, e.g. 99 or 99.9"},
                "threshold_ms": {"type": "number"},
            },
            "required": ["p", "threshold_ms"],
        },
    },
    "required": ["samples", "target"],
}


def latency_slo() -> Tool:
    return Tool(
        name="latency_slo",
        description=(
            "Tail-latency SLO calculator. op=report with 'samples' (latencies "
            "in ms) and 'target' ({p, threshold_ms}). Returns p50/p90/p95/p99/"
            "p999 (nearest-rank), the mean, and PASS/FAIL of the target "
            "percentile vs its threshold. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
