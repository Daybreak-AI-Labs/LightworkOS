"""Capability revocation propagation.

When a capability is revoked from a principal, every principal that holds that
capability *only* by transitive delegation from the revoked holder must lose it
too. Given a delegation graph (grants: principal -> grantee : capability) and a
revocation (principal, capability), compute the full set of principals that
transitively lose the capability via BFS over the grant edges for that
capability. Deterministic and offline.

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
        nodes.add(src)
        nodes.add(dst)

    # A principal loses the capability ONLY if it holds it solely by delegation
    # from the revoked holder -- i.e. EVERY grantor that delegated it to them has
    # also lost it. A principal with a surviving (independent) grant path, or a
    # native holder with no in-edges, keeps it. This is the fixpoint of
    # "lose iff all your grantors lost it"; the earlier BFS over-revoked anyone
    # merely reachable from the revoked holder, ignoring alternative paths.
    lost: set[str] = {principal}
    changed = True
    while changed:
        changed = False
        for n in nodes:
            if n in lost or n == principal:
                continue
            srcs = in_sources.get(n)
            if srcs and srcs <= lost:  # all of n's grantors have lost it
                lost.add(n)
                changed = True

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
            "that transitively loses the capability (BFS over that capability's "
            "grant edges). Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
