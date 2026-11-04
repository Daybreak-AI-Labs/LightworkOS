"""Capability negotiation protocol.

A requester asks for a set of capabilities; an offerer publishes the set it is
willing to grant plus optional constraints (which requested items are
``required`` for the requester, and a ``deny`` list the offerer refuses outright).
This resolves the negotiation deterministically and offline: the granted
intersection, the denied items with reasons, and whether the negotiation
SUCCEEDS — which it does only when every required capability was granted.

ops:
  - negotiate(requested, allowed[, required][, deny])

A requested capability is GRANTED when it is in ``allowed`` and not in ``deny``.
It is DENIED with reason "explicitly denied" (in ``deny``) or "not offered"
(absent from ``allowed``).
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _str_set(value: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for x in value or []:
        s = str(x).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _negotiate(args: dict[str, Any]) -> str:
    requested = _str_set(args.get("requested"))
    allowed = set(_str_set(args.get("allowed")))
    deny = set(_str_set(args.get("deny") or []))
    required = _str_set(args.get("required") or [])

    granted: list[str] = []
    denied: list[tuple[str, str]] = []
    for cap in requested:
        if cap in deny:
            denied.append((cap, "explicitly denied"))
        elif cap in allowed:
            granted.append(cap)
        else:
            denied.append((cap, "not offered"))

    granted_set = set(granted)
    missing_required = [r for r in required if r not in granted_set]
    succeeds = not missing_required

    verdict = "SUCCESS" if succeeds else "FAILURE"
    lines = [
        f"{verdict}: granted {len(granted)}/{len(requested)} requested "
        f"capabilit{'y' if len(requested) == 1 else 'ies'}",
        "granted: [" + ", ".join(granted) + "]",
    ]
    if denied:
        lines.append("denied:")
        lines.extend(f"  - {cap}: {reason}" for cap, reason in denied)
    else:
        lines.append("denied: []")
    if not succeeds:
        lines.append("unmet required: [" + ", ".join(missing_required) + "]")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "negotiate"):
        return f"ERROR: unknown op {args.get('op')!r} (expected negotiate)"
    if not isinstance(args.get("requested"), list):
        return "ERROR: requested (array of capability strings) is required"
    if not isinstance(args.get("allowed"), list):
        return "ERROR: allowed (array of capability strings) is required"
    return _negotiate(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["negotiate"]},
        "requested": {
            "type": "array",
            "description": "capabilities the requester asks for",
            "items": {"type": "string"},
        },
        "allowed": {
            "type": "array",
            "description": "capabilities the offerer is willing to grant",
            "items": {"type": "string"},
        },
        "required": {
            "type": "array",
            "description": "subset that MUST be granted for success",
            "items": {"type": "string"},
        },
        "deny": {
            "type": "array",
            "description": "capabilities the offerer refuses outright",
            "items": {"type": "string"},
        },
    },
    "required": ["requested", "allowed"],
}


def capability_negotiation() -> Tool:
    return Tool(
        name="capability_negotiation",
        description=(
            "Capability negotiation protocol. op=negotiate with 'requested' and "
            "'allowed' sets plus optional 'required' and 'deny'. Returns the "
            "granted intersection, the denied items with reasons (explicitly "
            "denied / not offered), and SUCCESS/FAILURE — succeeds only when "
            "every required capability is granted. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
