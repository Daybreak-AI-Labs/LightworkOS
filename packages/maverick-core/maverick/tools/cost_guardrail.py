"""Long-context cost guardrail.

Gate a run on its projected dollar cost before it executes. Deterministic and
offline: given the projected spend and a limit, return ALLOW well under budget,
WARN as it approaches (>=80% of the limit), and BLOCK once it exceeds a *hard*
limit. A soft limit (hard=false) never blocks — an over-budget run is downgraded
to a WARN so a human can decide — which is the safe default for advisory gates.

ops:
  - check(projected_dollars, [limit=50], [tokens], [hard=true])

Returns the decision plus the remaining headroom (limit - projected).
"""
from __future__ import annotations

from typing import Any

from . import Tool

_WARN_FRACTION = 0.80


def _check(projected: float, limit: float, hard: bool, tokens: float | None) -> str:
    headroom = limit - projected
    pct = (projected / limit * 100.0) if limit > 0 else float("inf")
    tok = f", tokens={tokens:g}" if tokens is not None else ""
    detail = (f"projected=${projected:.2f} limit=${limit:.2f} "
              f"({pct:.1f}% of limit) headroom=${headroom:.2f}{tok}")

    if projected > limit:
        if hard:
            return f"BLOCK: over hard limit — {detail}"
        return f"WARN: over soft limit (advisory, not blocked) — {detail}"
    if projected >= limit * _WARN_FRACTION:
        return f"WARN: at/above {int(_WARN_FRACTION * 100)}% of limit — {detail}"
    return f"ALLOW: under budget — {detail}"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r}"
    if args.get("projected_dollars") is None:
        return "ERROR: projected_dollars is required"
    try:
        projected = float(args.get("projected_dollars"))
    except (TypeError, ValueError):
        return "ERROR: projected_dollars must be a number"
    try:
        limit = float(args.get("limit", 50.0))
    except (TypeError, ValueError):
        return "ERROR: limit must be a number"
    if limit <= 0:
        return "ERROR: limit must be > 0"
    if projected < 0:
        return "ERROR: projected_dollars must be non-negative"

    tokens = args.get("tokens")
    if tokens is not None:
        try:
            tokens = float(tokens)
        except (TypeError, ValueError):
            return "ERROR: tokens must be a number"

    hard = args.get("hard", True)
    if not isinstance(hard, bool):
        return "ERROR: hard must be a boolean"

    return _check(projected, limit, hard, tokens)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "projected_dollars": {"type": "number", "description": "Projected run cost in USD"},
        "limit": {"type": "number", "description": "Dollar limit (default 50)"},
        "tokens": {"type": "number", "description": "Optional projected token count (informational)"},
        "hard": {"type": "boolean", "description": "Hard gate BLOCKs over-limit; soft WARNs (default true)"},
    },
    "required": ["projected_dollars"],
}


def cost_guardrail() -> Tool:
    return Tool(
        name="cost_guardrail",
        description=(
            "Long-context cost guardrail. op=check with 'projected_dollars', "
            "optional 'limit' (default 50), 'tokens', and 'hard' (default true). "
            "Returns ALLOW (under budget), WARN (>=80% of limit, or over a soft "
            "limit), or BLOCK (over a hard limit), plus remaining headroom. "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
