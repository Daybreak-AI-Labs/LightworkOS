"""Safety regression budget.

Gate a candidate release against a safety baseline: a candidate may regress a
safety score by at most ``allowed_regression``. Higher scores are better, so a
regression is ``baseline - candidate``; it passes when that drop stays within
budget. Supports a single metric, or a list of per-metric budgets (the gate
fails if ANY metric blows its budget). Deterministic and offline. No disk.

ops:
  - check(baseline, candidate, allowed_regression)
  - check(metrics=[{name, baseline, candidate, budget}])
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _num(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _eval_one(baseline: float, candidate: float, budget: float) -> tuple[bool, float, float]:
    """Return (passed, regression, remaining_budget)."""
    regression = baseline - candidate  # >0 means the score dropped
    remaining = budget - max(regression, 0.0)
    passed = regression <= budget
    return passed, regression, remaining


def _check_single(args: dict[str, Any]) -> str:
    baseline = _num(args.get("baseline"))
    candidate = _num(args.get("candidate"))
    budget = _num(args.get("allowed_regression"))
    if baseline is None or candidate is None:
        return "ERROR: baseline and candidate (numbers) are required"
    if budget is None or budget < 0:
        return "ERROR: allowed_regression (number >= 0) is required"

    passed, regression, remaining = _eval_one(baseline, candidate, budget)
    verdict = "PASS" if passed else "FAIL"
    return (
        f"{verdict}: regression {regression:+g} vs budget {budget:g}, "
        f"remaining {remaining:g} (baseline {baseline:g} -> candidate {candidate:g})"
    )


def _check_multi(metrics: list) -> str:
    rows: list[tuple[str, bool, float, float]] = []
    for m in metrics:
        if not isinstance(m, dict):
            return "ERROR: each metric must be an object {name, baseline, candidate, budget}"
        name = str(m.get("name") or "").strip()
        if not name:
            return "ERROR: each metric needs a name"
        baseline = _num(m.get("baseline"))
        candidate = _num(m.get("candidate"))
        budget = _num(m.get("budget"))
        if baseline is None or candidate is None:
            return f"ERROR: metric {name!r} needs numeric baseline and candidate"
        if budget is None or budget < 0:
            return f"ERROR: metric {name!r} needs budget >= 0"
        passed, regression, remaining = _eval_one(baseline, candidate, budget)
        rows.append((name, passed, regression, remaining))

    failed = [r for r in rows if not r[1]]
    overall = "FAIL" if failed else "PASS"
    lines = [
        f"{overall}: {len(rows) - len(failed)}/{len(rows)} metric(s) within budget",
    ]
    for name, passed, regression, remaining in rows:
        tag = "PASS" if passed else "FAIL"
        lines.append(f"  - {name}: {tag} regression {regression:+g}, remaining {remaining:g}")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r} (expected check)"
    metrics = args.get("metrics")
    if metrics is not None:
        if not isinstance(metrics, list) or not metrics:
            return "ERROR: metrics must be a non-empty array of {name, baseline, candidate, budget}"
        return _check_multi(metrics)
    return _check_single(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "baseline": {"type": "number", "description": "baseline safety score (higher is better)"},
        "candidate": {"type": "number", "description": "candidate safety score"},
        "allowed_regression": {
            "type": "number",
            "description": "max permitted drop (baseline - candidate)",
        },
        "metrics": {
            "type": "array",
            "description": "per-metric budgets; fails if ANY exceeds its budget",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "baseline": {"type": "number"},
                    "candidate": {"type": "number"},
                    "budget": {"type": "number"},
                },
                "required": ["name", "baseline", "candidate", "budget"],
            },
        },
    },
    "required": ["op"],
}


def safety_regression_budget() -> Tool:
    return Tool(
        name="safety_regression_budget",
        description=(
            "Safety regression budget gate. op=check with either {baseline, "
            "candidate, allowed_regression} for a single metric, or 'metrics' "
            "([{name, baseline, candidate, budget}]) for many. Higher scores are "
            "better; passes when the drop (baseline - candidate) stays within "
            "budget. Returns PASS/FAIL and the remaining budget. Deterministic, "
            "offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
