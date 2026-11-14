"""SLA-breach automation.

Check recent measurements against an SLO and, on a breach, recommend the
escalating response action (throttle -> page -> failover) by severity. The
caller supplies the SLO and measurements; this resolves OK or BREACH with the
breaching points. Deterministic and offline.

A measurement breaches when it violates the comparator:
  - ``lt``: healthy means value < threshold; a breach is value >= threshold.
  - ``gt``: healthy means value > threshold; a breach is value <= threshold.

Severity scales with how many of the windowed measurements breach:
  - < 50% breaching  -> minor   -> action: throttle
  - 50%..< 100%      -> major   -> action: page
  - 100% breaching   -> critical-> action: failover

ops:
  - check(slo, measurements)  — OK / BREACH + breaching points + action.

SLO:          ``{"metric", "threshold", "window", "comparator": "lt"|"gt"}``.
Measurements: ``[{"t", "value"}]`` (most recent last).
"""
from __future__ import annotations

import math
from typing import Any

from . import Tool

# Severity -> recommended automated action.
_ACTIONS = {"minor": "throttle", "major": "page", "critical": "failover"}


def _check(slo: dict, measurements: list) -> str:
    metric = slo.get("metric")
    if not isinstance(metric, str) or not metric.strip():
        return "ERROR: slo.metric (string) is required"
    comparator = str(slo.get("comparator", "")).strip().lower()
    if comparator not in ("lt", "gt"):
        return "ERROR: slo.comparator must be 'lt' or 'gt'"
    try:
        threshold = float(slo.get("threshold"))
    except (TypeError, ValueError):
        return "ERROR: slo.threshold (number) is required"
    if not math.isfinite(threshold):
        return "ERROR: slo.threshold must be a finite number"
    try:
        window = int(slo.get("window"))
    except (TypeError, ValueError, OverflowError):
        return "ERROR: slo.window (integer) is required"
    if window <= 0:
        return "ERROR: slo.window must be > 0"

    parsed: list[tuple[Any, float]] = []
    for mm in measurements:
        if not isinstance(mm, dict):
            return "ERROR: each measurement must be an object"
        try:
            value = float(mm.get("value"))
        except (TypeError, ValueError):
            return "ERROR: each measurement needs a numeric value"
        if math.isnan(value):
            # NaN compares false both ways, so it would never breach.
            return "ERROR: measurement values must not be NaN"
        parsed.append((mm.get("t"), value))

    # Evaluate the most recent `window` measurements (window tail).
    windowed = parsed[-window:]

    def breaches(v: float) -> bool:
        # Breach = SLO violated. lt: healthy v<thr, breach v>=thr.
        return v >= threshold if comparator == "lt" else v <= threshold

    breaching = [(t, v) for t, v in windowed if breaches(v)]
    n = len(windowed)
    b = len(breaching)

    if b == 0:
        return (
            f"OK metric={metric} comparator={comparator} threshold={threshold:g} "
            f"breaching=0/{n}"
        )

    frac = b / n
    if frac >= 1.0:
        severity = "critical"
    elif frac >= 0.5:
        severity = "major"
    else:
        severity = "minor"
    action = _ACTIONS[severity]

    pts = ", ".join(f"{t}={v:g}" for t, v in breaching)
    return (
        f"BREACH metric={metric} severity={severity} action={action} "
        f"breaching={b}/{n} (threshold {comparator} {threshold:g})\n"
        f"  breaching_points: [{pts}]"
    )


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r}"
    slo = args.get("slo")
    if not isinstance(slo, dict):
        return "ERROR: slo ({metric, threshold, window, comparator}) is required"
    measurements = args.get("measurements")
    if not isinstance(measurements, list) or not measurements:
        return "ERROR: measurements (non-empty list of {t, value}) is required"
    return _check(slo, measurements)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "slo": {
            "type": "object",
            "description": "SLO: {metric, threshold, window, comparator: lt|gt}",
            "properties": {
                "metric": {"type": "string"},
                "threshold": {"type": "number"},
                "window": {"type": "integer", "description": "How many recent measurements to evaluate"},
                "comparator": {"type": "string", "enum": ["lt", "gt"]},
            },
            "required": ["metric", "threshold", "window", "comparator"],
        },
        "measurements": {
            "type": "array",
            "description": "Recent measurements (most recent last): {t, value}",
            "items": {
                "type": "object",
                "properties": {
                    "t": {"type": ["string", "number"]},
                    "value": {"type": "number"},
                },
                "required": ["t", "value"],
            },
        },
    },
    "required": ["slo", "measurements"],
}


def sla_breach() -> Tool:
    return Tool(
        name="sla_breach",
        description=(
            "SLA-breach automation. op=check with 'slo' ({metric, threshold, "
            "window, comparator: lt|gt}) and 'measurements' ({t, value}). "
            "Evaluates the most recent `window` measurements; on a breach returns "
            "the breaching points and an escalating action (throttle/page/failover) "
            "by severity (minor/major/critical). Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
