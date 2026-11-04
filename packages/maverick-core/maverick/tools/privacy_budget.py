"""Stateless privacy-budget calculator.

Given a trusted cumulative differential-privacy spend (total epsilon), report
the remaining budget and whether a proposed new query fits in that remainder.
This tool deliberately does not store per-user state or consume budget; callers
must provide authoritative spend from their own ledger.

ops:
  - check(budget, spent[, request])  — remaining budget, and (if 'request'
    given) whether the next query at that epsilon fits.
"""
from __future__ import annotations

from typing import Any

from . import Tool

_EPS = 1e-9  # float-comparison slack


def _sum_spent(spent: Any) -> tuple[float | None, str]:
    if isinstance(spent, (int, float)) and not isinstance(spent, bool):
        v = float(spent)
        return (v, "") if v >= 0 else (None, "ERROR: spent must be >= 0")
    if isinstance(spent, list):
        total = 0.0
        for e in spent:
            if isinstance(e, bool) or not isinstance(e, (int, float)) or e < 0:
                return None, f"ERROR: each spent epsilon must be a number >= 0 (got {e!r})"
            total += float(e)
        return total, ""
    return None, "ERROR: spent must be a number or an array of epsilons"


def _check(args: dict[str, Any]) -> str:
    budget = args.get("budget")
    if isinstance(budget, bool) or not isinstance(budget, (int, float)) or budget <= 0:
        return "ERROR: budget must be a number > 0"
    if "spent" not in args:
        return "ERROR: spent is required from a trusted cumulative ledger"
    spent_total, err = _sum_spent(args.get("spent"))
    if err:
        return err
    assert spent_total is not None
    remaining = float(budget) - spent_total

    lines = [
        "WARNING: stateless estimate only; does not persist or consume privacy budget",
        f"budget: {budget:g}",
        f"spent: {spent_total:g}",
        f"remaining: {remaining:g}",
    ]
    if "request" in args:
        req = args.get("request")
        if isinstance(req, bool) or not isinstance(req, (int, float)) or req < 0:
            return "ERROR: request must be a number >= 0"
        allowed = float(req) <= remaining + _EPS
        verdict = "FITS" if allowed else "DENIED"
        lines.append(
            f"request: {req:g} -> {verdict}"
            + ("" if allowed else f" (exceeds remaining by {float(req) - remaining:g})")
        )
    elif remaining <= _EPS:
        lines.append("budget exhausted")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r}"
    if "budget" not in args:
        return "ERROR: budget is required"
    return _check(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "budget": {"type": "number", "description": "total epsilon budget (>0)"},
        "spent": {
            "description": "epsilon already consumed: a number, or an array of per-query epsilons",
            "oneOf": [{"type": "number"}, {"type": "array", "items": {"type": "number"}}],
        },
        "request": {"type": "number", "description": "epsilon of a proposed next query (optional)"},
    },
    "required": ["budget", "spent"],
}


def privacy_budget() -> Tool:
    return Tool(
        name="privacy_budget",
        description=(
            "Stateless differential-privacy budget calculator. op=check with "
            "'budget' (total epsilon), required trusted cumulative 'spent' "
            "(a number or array of consumed epsilons), and optional 'request' "
            "(epsilon of a proposed query). Reports remaining budget and, for "
            "a request, FITS/DENIED. Does not persist or consume per-user "
            "budget; pair with an authoritative ledger for enforcement."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
