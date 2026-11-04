"""Crypto budget receipt tool — issue + verify an HMAC-signed receipt.

Bind a dollar spend to a goal with a tamper-evident receipt: issue a receipt
``goal|dollars|hexmac`` signed with a shared secret, and later verify that a
presented receipt is authentic and unmodified. Deterministic given the key;
offline; pure stdlib (hmac + hashlib.sha256). No disk, no network.

ops:
  - issue(goal_id, dollars, key)  -> receipt string "goal|dollars|hexmac".
  - verify(receipt, key)          -> VALID / INVALID.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

from . import Tool


def _fmt_dollars(value: Any) -> tuple[str | None, str | None]:
    """Canonicalise the dollar amount to a fixed 2-dp string."""
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return None, "dollars must be a number"
    if amount < 0:
        return None, "dollars must be non-negative"
    return f"{amount:.2f}", None


def _mac(goal: str, dollars: str, key: str) -> str:
    msg = f"{goal}|{dollars}".encode()
    return hmac.new(key.encode(), msg, hashlib.sha256).hexdigest()


def _issue(args: dict[str, Any]) -> str:
    goal = str(args.get("goal_id") or "").strip()
    if not goal:
        return "ERROR: goal_id is required"
    if "|" in goal:
        return "ERROR: goal_id must not contain '|'"
    key = args.get("key")
    if not isinstance(key, str) or not key:
        return "ERROR: key is required"
    dollars, err = _fmt_dollars(args.get("dollars"))
    if err:
        return f"ERROR: {err}"
    return f"OK: {goal}|{dollars}|{_mac(goal, dollars, key)}"


def _verify(args: dict[str, Any]) -> str:
    receipt = args.get("receipt")
    if not isinstance(receipt, str) or not receipt.strip():
        return "ERROR: receipt is required"
    key = args.get("key")
    if not isinstance(key, str) or not key:
        return "ERROR: key is required"
    # Strip an optional "OK: " prefix so a freshly issued receipt round-trips.
    body = receipt.strip()
    if body.startswith("OK:"):
        body = body[len("OK:"):].strip()
    parts = body.split("|")
    if len(parts) != 3:
        return "INVALID: malformed receipt (expected goal|dollars|hexmac)"
    goal, dollars, mac = parts
    expected = _mac(goal, dollars, key)
    if hmac.compare_digest(expected.encode(), mac.strip().encode()):
        return f"VALID: goal={goal} dollars={dollars}"
    return "INVALID: signature mismatch"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "issue":
        return _issue(args)
    if op == "verify":
        return _verify(args)
    return f"ERROR: unknown op {op!r} (expected issue or verify)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["issue", "verify"]},
        "goal_id": {"type": "string", "description": "goal id for op=issue"},
        "dollars": {"type": "number", "description": "spend amount for op=issue"},
        "receipt": {"type": "string", "description": "receipt to check for op=verify"},
        "key": {"type": "string", "description": "shared HMAC secret"},
    },
    "required": ["op", "key"],
}


def crypto_budget_receipt() -> Tool:
    return Tool(
        name="crypto_budget_receipt",
        description=(
            "Issue or verify an HMAC-SHA256 budget receipt. op=issue with "
            "{goal_id, dollars, key} returns 'goal|dollars|hexmac'. op=verify "
            "with {receipt, key} returns VALID/INVALID. Deterministic given the "
            "key; offline; stdlib hmac+hashlib only."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
