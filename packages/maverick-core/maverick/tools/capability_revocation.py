"""Capability revocation propagation.

When a capability is revoked from a principal, every principal that holds that
capability *only* by transitive delegation from the revoked holder must lose it
too. Given a delegation graph (grants: principal -> grantee : capability) and a
revocation (principal, capability), compute the full set of principals that
transitively lose the capability: those downstream of it that no other native
holder still reaches along that capability's grant edges. Deterministic and
offline.

ops:
  - propagate(grants, principal, capability)  — grants: [{from,to,capability}].
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from . import Tool


def _propagate(grants: list[dict], principal: str, capability: str) -> str:
    # Build the in-edges for THIS capability only: who granted the capability
    # TO each principal. A principal can hold it via several grantors.
    in_sources: defaultdict[str, set[str]] = defaultdict(set)
    out_edges: defaultdict[str, set[str]] = defaultdict(set)
    nodes: set[str] = set()
    for g in grants:
        if not isinstance(g, dict):
            continue
        if str(g.get("capability", "")).strip() != capability:
            continue
        src = str(g.get("from", "")).strip()
        dst = str(g.get("to", "")).strip()
        if not src or not dst:
            continue
        in_sources[dst].add(src)
        out_edges[src].add(dst)
        nodes.add(src)
        nodes.add(dst)

    def _reach(starts: set[str]) -> set[str]:
        seen = set(starts)
        queue = list(starts)
        while queue:
            for nxt in out_edges.get(queue.pop(), ()):
                if nxt != principal and nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        return seen

    # A principal keeps the capability iff some native holder (a node with no
    # grantor, other than the revoked one) still reaches it along grant edges
    # that do not pass through the revoked holder. Everyone downstream of the
    # revoked holder without such a path loses it -- including principals that
    # only granted it to each other in a cycle.
    roots = {n for n in nodes if n != principal and not in_sources.get(n)}
    surviving = _reach(roots)
    lost = (_reach({principal}) - surviving) | {principal}

    affected = sorted(lost - {principal})
    if not affected:
        return (f"REVOKED {capability!r} from {principal}: "
                f"no downstream principals affected")
    return (f"REVOKED {capability!r} from {principal}: "
            f"{len(affected)} principal(s) transitively lose it:\n- "
            + "\n- ".join(affected))


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "propagate"):
        return f"ERROR: unknown op {args.get('op')!r}"
    grants = args.get("grants")
    if not isinstance(grants, list):
        return "ERROR: grants (list of {from,to,capability}) is required"
    principal = str(args.get("principal") or "").strip()
    if not principal:
        return "ERROR: principal (the revoked holder) is required"
    capability = str(args.get("capability") or "").strip()
    if not capability:
        return "ERROR: capability is required"
    return _propagate(grants, principal, capability)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["propagate"]},
        "grants": {
            "type": "array",
            "description": "Delegation grants: {from, to, capability}",
            "items": {"type": "object"},
        },
        "principal": {"type": "string", "description": "Holder the capability is revoked from"},
        "capability": {"type": "string", "description": "Capability being revoked"},
    },
    "required": ["grants", "principal", "capability"],
}


def capability_revocation() -> Tool:
    return Tool(
        name="capability_revocation",
        description=(
            "Propagate a capability revocation through a delegation graph. "
            "op=propagate with 'grants' ([{from,to,capability}]), 'principal' "
            "(the revoked holder), and 'capability'. Returns every principal "
            "that transitively loses the capability (no surviving grant path from "
            "another native holder). Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
