"""Cost-of-quality study helper.

Quantify how much of a run budget went to *successful* work versus retries and
failed attempts — the "cost of poor quality" view. Deterministic and offline:
given per-run cost and a pass/fail flag, this splits total spend into passing vs
failing, derives the cost per successful run, and the wasted-spend ratio (the
share of dollars that did not end in a success).

ops:
  - analyze(runs)  — runs: [{cost, passed(bool), retries?}].
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _analyze(runs: list) -> str:
    total = 0.0
    pass_spend = 0.0
    fail_spend = 0.0
    passes = 0
    fails = 0
    retries = 0
    for r in runs:
        if not isinstance(r, dict):
            return "ERROR: each run must be an object {cost, passed, retries?}"
        try:
            cost = float(r.get("cost", 0) or 0)
        except (TypeError, ValueError):
            return "ERROR: every run needs a numeric 'cost'"
        passed = r.get("passed")
        if not isinstance(passed, bool):
            return "ERROR: every run needs a boolean 'passed'"
        try:
            retries += int(r.get("retries", 0) or 0)
        except (TypeError, ValueError, OverflowError):
            return "ERROR: 'retries' must be an integer"
        total += cost
        if passed:
            pass_spend += cost
            passes += 1
        else:
            fail_spend += cost
            fails += 1

    cost_per_success = (total / passes) if passes else float("inf")
    wasted_ratio = (fail_spend / total) if total > 0 else 0.0
    cps = "n/a (no successes)" if passes == 0 else f"${cost_per_success:.4f}"
    return (f"OK runs={len(runs)} passed={passes} failed={fails} retries={retries}\n"
            f"  total_spend=${total:.4f}\n"
            f"  passing_spend=${pass_spend:.4f}  failing_spend=${fail_spend:.4f}\n"
            f"  cost_per_success={cps}\n"
            f"  wasted_spend_ratio={wasted_ratio:.4f}")


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "analyze"):
        return f"ERROR: unknown op {args.get('op')!r}"
    runs = args.get("runs")
    if not isinstance(runs, list) or not runs:
        return "ERROR: runs (non-empty list of {cost, passed, retries?}) is required"
    return _analyze(runs)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["analyze"]},
        "runs": {
            "type": "array",
            "description": "Runs: [{cost, passed(bool), retries?}]",
            "items": {
                "type": "object",
                "properties": {
                    "cost": {"type": "number"},
                    "passed": {"type": "boolean"},
                    "retries": {"type": "integer"},
                },
            },
        },
    },
    "required": ["runs"],
}


def cost_of_quality() -> Tool:
    return Tool(
        name="cost_of_quality",
        description=(
            "Cost-of-quality study helper. op=analyze with 'runs' "
            "([{cost, passed(bool), retries?}]). Returns total spend, spend on "
            "passing vs failing runs, cost-per-success, and the wasted-spend "
            "ratio (failing dollars / total). Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
