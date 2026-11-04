"""Capability-delegation validator.

Checks a set of capability delegations for **privilege escalation**: nobody may
grant a capability they don't themselves hold. Starting from each principal's
root capabilities, it applies the delegation edges to a fixpoint; any grant
whose grantor never legitimately holds the capability (directly or via a valid
chain — including purely circular grants with no root source) is flagged as
unauthorized. Deterministic and offline.

ops:
  - validate(roots, grants)  — VALID + effective holdings, or the unauthorized
    grants. ``roots`` is ``{principal: [caps]}``; ``grants`` is a list of
    ``{from, to, cap}``.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _validate(roots: dict, grants: list) -> str:
    holdings: dict[str, set[str]] = {}
    for who, caps in roots.items():
        holdings.setdefault(str(who), set()).update(str(c) for c in (caps or []))

    edges = []
    for g in grants:
        if not isinstance(g, dict) or not all(k in g for k in ("from", "to", "cap")):
            return "ERROR: each grant needs 'from', 'to', and 'cap'"
        edges.append((str(g["from"]), str(g["to"]), str(g["cap"])))

    applied = [False] * len(edges)
    progress = True
    while progress:
        progress = False
        for i, (frm, to, cap) in enumerate(edges):
            if applied[i]:
                continue
            if cap in holdings.get(frm, set()):
                holdings.setdefault(to, set()).add(cap)
                applied[i] = True
                progress = True

    violations = [edges[i] for i in range(len(edges)) if not applied[i]]
    if violations:
        lines = [f"INVALID: {len(violations)} unauthorized delegation(s):"]
        for frm, to, cap in violations:
            lines.append(f"  {frm} -> {to}: {cap!r} (grantor does not hold {cap!r})")
        return "\n".join(lines)

    lines = ["VALID: all delegations authorized", "effective holdings:"]
    for who in sorted(holdings):
        caps = ", ".join(sorted(holdings[who]))
        lines.append(f"  {who}: {caps}" if caps else f"  {who}: (none)")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "validate"):
        return f"ERROR: unknown op {args.get('op')!r}"
    roots = args.get("roots", {})
    grants = args.get("grants")
    if not isinstance(roots, dict):
        return "ERROR: roots must be an object {principal: [caps]}"
    if not isinstance(grants, list):
        return "ERROR: grants must be an array of {from, to, cap}"
    return _validate(roots, grants)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["validate"]},
        "roots": {
            "type": "object",
            "description": "principal -> list of root capabilities they natively hold",
        },
        "grants": {
            "type": "array",
            "description": "delegation edges; each {from, to, cap}",
            "items": {
                "type": "object",
                "properties": {
                    "from": {"type": "string"},
                    "to": {"type": "string"},
                    "cap": {"type": "string"},
                },
                "required": ["from", "to", "cap"],
            },
        },
    },
    "required": ["grants"],
}


def capability_delegation() -> Tool:
    return Tool(
        name="capability_delegation",
        description=(
            "Validate a capability-delegation graph for privilege escalation: "
            "nobody may grant a capability they don't hold. op=validate with "
            "'roots' ({principal: [caps]}) and 'grants' ([{from, to, cap}]). "
            "Applies grants to a fixpoint from the roots; reports VALID + "
            "effective holdings, or the unauthorized delegations (incl. purely "
            "circular grants with no root source). Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
