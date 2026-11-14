"""Query-plan regression check.

Compare a baseline query plan against a candidate plan and flag a performance
regression before it ships. Deterministic and offline: the caller supplies both
plans (each ``{rows_scanned, cost, used_index}``) and a cost tolerance; this
resolves OK or REGRESSION with the specific reasons.

A candidate regresses when ANY of:
  - its cost rises more than ``threshold_pct`` over the baseline cost;
  - it dropped an index the baseline used (``used_index`` true -> false);
  - it scans more rows than the baseline.

ops:
  - compare(baseline, candidate, threshold_pct?)  — OK / REGRESSION + details.

Plans: ``{"rows_scanned": int, "cost": number, "used_index": bool}``.
``threshold_pct`` defaults to 10 (percent cost increase tolerated).
"""
from __future__ import annotations

from typing import Any

from . import Tool, as_bool

_DEFAULT_THRESHOLD_PCT = 10.0


def _parse_plan(plan: Any, label: str) -> tuple[dict[str, Any] | None, str]:
    if not isinstance(plan, dict):
        return None, f"ERROR: {label} (object with rows_scanned/cost/used_index) is required"
    try:
        rows = int(plan.get("rows_scanned"))
        cost = float(plan.get("cost"))
    except (TypeError, ValueError, OverflowError):
        return None, f"ERROR: {label} needs numeric rows_scanned and cost"
    if rows < 0 or cost < 0:
        return None, f"ERROR: {label} rows_scanned and cost must be >= 0"
    used_index = as_bool(plan.get("used_index", False))
    return {"rows_scanned": rows, "cost": cost, "used_index": used_index}, ""


def _compare(baseline: Any, candidate: Any, threshold_pct: float) -> str:
    base, err = _parse_plan(baseline, "baseline")
    if err:
        return err
    cand, err = _parse_plan(candidate, "candidate")
    if err:
        return err

    reasons: list[str] = []

    # Cost regression: percent increase over baseline beyond tolerance.
    if base["cost"] == 0:
        cost_up_pct = float("inf") if cand["cost"] > 0 else 0.0
    else:
        cost_up_pct = (cand["cost"] - base["cost"]) / base["cost"] * 100.0
    if cost_up_pct > threshold_pct:
        reasons.append(
            f"cost up {cost_up_pct:.1f}% ({base['cost']:g} -> {cand['cost']:g}), "
            f"tolerance {threshold_pct:g}%"
        )

    # Index dropped.
    if base["used_index"] and not cand["used_index"]:
        reasons.append("index dropped (baseline used an index, candidate does not)")

    # More rows scanned.
    if cand["rows_scanned"] > base["rows_scanned"]:
        reasons.append(
            f"rows_scanned up ({base['rows_scanned']} -> {cand['rows_scanned']})"
        )

    if not reasons:
        return (
            f"OK no regression (cost {base['cost']:g} -> {cand['cost']:g}, "
            f"{cost_up_pct:+.1f}% within {threshold_pct:g}%; "
            f"rows {base['rows_scanned']} -> {cand['rows_scanned']}; "
            f"index {base['used_index']} -> {cand['used_index']})"
        )
    return "REGRESSION " + "; ".join(reasons)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "compare"):
        return f"ERROR: unknown op {args.get('op')!r}"
    baseline = args.get("baseline")
    candidate = args.get("candidate")
    if not isinstance(baseline, dict):
        return "ERROR: baseline ({rows_scanned, cost, used_index}) is required"
    if not isinstance(candidate, dict):
        return "ERROR: candidate ({rows_scanned, cost, used_index}) is required"
    raw_threshold = args.get("threshold_pct", _DEFAULT_THRESHOLD_PCT)
    try:
        threshold_pct = float(raw_threshold)
    except (TypeError, ValueError):
        return "ERROR: threshold_pct must be a number"
    if threshold_pct < 0:
        return "ERROR: threshold_pct must be >= 0"
    return _compare(baseline, candidate, threshold_pct)


def _plan_schema(desc: str) -> dict[str, Any]:
    return {
        "type": "object",
        "description": desc,
        "properties": {
            "rows_scanned": {"type": "integer", "minimum": 0},
            "cost": {"type": "number", "minimum": 0},
            "used_index": {"type": "boolean"},
        },
        "required": ["rows_scanned", "cost"],
    }


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["compare"]},
        "baseline": _plan_schema("Baseline plan: {rows_scanned, cost, used_index}"),
        "candidate": _plan_schema("Candidate plan: {rows_scanned, cost, used_index}"),
        "threshold_pct": {
            "type": "number",
            "minimum": 0,
            "description": "Cost increase tolerated before flagging (percent, default 10)",
        },
    },
    "required": ["baseline", "candidate"],
}


def query_plan_regression() -> Tool:
    return Tool(
        name="query_plan_regression",
        description=(
            "Query-plan regression check. op=compare with 'baseline' and "
            "'candidate' plans (each {rows_scanned, cost, used_index}) and an "
            "optional 'threshold_pct' (cost-increase tolerance, default 10). "
            "Flags a REGRESSION when cost rises beyond the tolerance, an index "
            "the baseline used was dropped, or more rows are scanned; otherwise "
            "OK. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
