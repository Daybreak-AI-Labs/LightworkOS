"""format_money tool — localized money display (offline, no live FX).

The display counterpart to the ``currency`` tool (which does live-FX
conversion): format an amount for a (locale, currency) pair, optionally
converting with an operator-supplied rate.

ops:
  - format(amount, currency?, locale?, rate?)   — formatted string
  - supported()                                 — known locales + currencies
"""
from __future__ import annotations

from typing import Any

from . import Tool

_FMT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["format", "supported"]},
        "amount": {"type": "number"},
        "currency": {"type": "string", "description": "ISO code, e.g. EUR (default USD)"},
        "locale": {"type": "string", "description": "e.g. de-DE (default en-US)"},
        "rate": {"type": "number", "description": "optional FX rate from the base amount"},
    },
}


def _run(args: dict[str, Any]) -> str:
    op = args.get("op") or "format"
    from ..money_format import format_money, supported
    if op == "supported":
        s = supported()
        return ("locales: " + ", ".join(s["locales"]) +
                "\ncurrencies: " + ", ".join(s["currencies"]))
    if op == "format":
        if args.get("amount") is None:
            return "ERROR: amount is required"
        try:
            return format_money(
                float(args["amount"]),
                currency=str(args.get("currency") or "USD"),
                locale=str(args.get("locale") or "en-US"),
                rate=float(args["rate"]) if args.get("rate") is not None else None,
            )
        except (TypeError, ValueError) as e:
            return f"ERROR: {e}"
    return f"ERROR: unknown op {op!r}"


def format_money_tool() -> Tool:
    return Tool(
        name="format_money",
        description=(
            "Localized money display (offline). ops: format (amount + optional "
            "currency/locale/rate), supported. No live FX -- pass rate to "
            "convert. For live conversion use the 'currency' tool."
        ),
        input_schema=_FMT_SCHEMA,
        fn=_run,
    )
