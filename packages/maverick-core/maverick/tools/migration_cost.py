"""Provider migration cost calculator.

Given a month of usage and two price books, work out what that usage would cost
on each provider and whether switching is worth it. Deterministic and offline:
the caller supplies the token/request counts and the per-million-token prices;
this resolves the monthly bills, the dollar delta, and the percent savings of
moving from the first ("from") provider to the second ("to").

ops:
  - compare(usage, from, to)  — monthly cost on each + delta + % savings.

Prices are per MILLION tokens (per_mtok); an optional flat ``per_request`` is
added per request. A positive saving means the "to" provider is cheaper.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _cost(usage: dict, book: dict) -> float:
    """Monthly dollar cost of ``usage`` under price ``book``."""
    in_tok = float(usage.get("input_tokens", 0) or 0)
    out_tok = float(usage.get("output_tokens", 0) or 0)
    reqs = float(usage.get("requests", 0) or 0)
    in_rate = float(book.get("input_per_mtok", 0) or 0)
    out_rate = float(book.get("output_per_mtok", 0) or 0)
    per_req = float(book.get("per_request", 0) or 0)
    return (in_tok / 1_000_000.0) * in_rate + (out_tok / 1_000_000.0) * out_rate + reqs * per_req


def _compare(usage: dict, frm: dict, to: dict) -> str:
    a = _cost(usage, frm)
    b = _cost(usage, to)
    delta = a - b  # positive => "to" is cheaper => savings
    pct = (delta / a * 100.0) if a > 0 else 0.0
    a_name = str(frm.get("name", "from"))
    b_name = str(to.get("name", "to"))
    if delta > 0:
        verdict = f"SWITCH to {b_name}: save ${delta:.2f}/mo ({pct:.1f}%)"
    elif delta < 0:
        verdict = f"STAY on {a_name}: switching costs ${-delta:.2f}/mo more ({pct:.1f}%)"
    else:
        verdict = "EVEN: both providers cost the same"
    return (f"{verdict}\n"
            f"  {a_name}: ${a:.2f}/mo\n"
            f"  {b_name}: ${b:.2f}/mo\n"
            f"  delta=${delta:.2f}/mo  savings={pct:.1f}%")


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "compare"):
        return f"ERROR: unknown op {args.get('op')!r}"
    usage = args.get("usage")
    frm = args.get("from")
    to = args.get("to")
    if not isinstance(usage, dict):
        return "ERROR: usage ({input_tokens, output_tokens, requests}) is required"
    if not isinstance(frm, dict) or not isinstance(to, dict):
        return "ERROR: 'from' and 'to' price books are required"
    try:
        return _compare(usage, frm, to)
    except (TypeError, ValueError):
        return "ERROR: usage counts and prices must be numbers"


_BOOK_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "input_per_mtok": {"type": "number", "description": "USD per 1M input tokens"},
        "output_per_mtok": {"type": "number", "description": "USD per 1M output tokens"},
        "per_request": {"type": "number", "description": "Optional flat USD per request"},
    },
}

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["compare"]},
        "usage": {
            "type": "object",
            "description": "Monthly usage: {input_tokens, output_tokens, requests}",
            "properties": {
                "input_tokens": {"type": "number"},
                "output_tokens": {"type": "number"},
                "requests": {"type": "number"},
            },
        },
        "from": _BOOK_SCHEMA,
        "to": _BOOK_SCHEMA,
    },
    "required": ["usage", "from", "to"],
}


def migration_cost() -> Tool:
    return Tool(
        name="migration_cost",
        description=(
            "Provider migration cost calculator. op=compare with 'usage' "
            "({input_tokens, output_tokens, requests}) and two price books "
            "'from'/'to' ({name, input_per_mtok, output_per_mtok, per_request?}). "
            "Returns the monthly cost on each provider, the dollar delta, and the "
            "percent savings of switching. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
