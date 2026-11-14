"""Capability delegation graph.

Build a directed graph of capability grants (principal -> grantee : capability)
and analyze it for governance risks: delegation cycles (A grants to B grants
back to A), over-broad fan-out (one principal granting to many), and direct
holders of a capability named as ``sensitive``. Escalation through a chain of
grants is not traced. Deterministic and offline.

ops:
  - analyze(grants, [sensitive])  — grants: [{from, to, capability}].
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from . import Tool


def _find_cycles(edges: dict[str, set[str]]) -> list[list[str]]:
    cycles: list[list[str]] = []
    seen_pairs: set[tuple] = set()
    color: dict[str, int] = {}
    stack: list[str] = []

    def dfs(node: str) -> None:
        color[node] = 1
        stack.append(node)
        for nxt in sorted(edges.get(node, ())):
            if color.get(nxt, 0) == 1:  # back-edge -> cycle
                if nxt in stack:
                    cyc = stack[stack.index(nxt):] + [nxt]
                    key = tuple(sorted(set(cyc)))
                    if key not in seen_pairs:
                        seen_pairs.add(key)
                        cycles.append(cyc)
            elif color.get(nxt, 0) == 0:
                dfs(nxt)
        stack.pop()
        color[node] = 2

    for n in sorted(edges):
        if color.get(n, 0) == 0:
            dfs(n)
    return cycles


def _analyze(grants: list[dict], sensitive: set[str]) -> str:
    edges: defaultdict[str, set[str]] = defaultdict(set)
    cap_by_holder: defaultdict[str, set[str]] = defaultdict(set)
    fanout: defaultdict[str, set[str]] = defaultdict(set)

    for g in grants:
        if not isinstance(g, dict):
            continue
        src = str(g.get("from", "")).strip()
        dst = str(g.get("to", "")).strip()
        cap = str(g.get("capability", "")).strip()
        if not src or not dst:
            continue
        edges[src].add(dst)
        fanout[src].add(dst)
        if cap:
            cap_by_holder[dst].add(cap)

    findings: list[str] = []

    for cyc in _find_cycles(edges):
        findings.append("delegation-cycle: " + " -> ".join(cyc))

    for src, grantees in sorted(fanout.items()):
        if len(grantees) >= 5:
            findings.append(f"over-broad fan-out: {src} grants to {len(grantees)} principals")

    if sensitive:
        for holder, caps in sorted(cap_by_holder.items()):
            hit = sorted(caps & sensitive)
            if hit:
                findings.append(f"sensitive-capability holder: {holder} holds {', '.join(hit)}")

    if not findings:
        return f"CLEAN: {len(grants)} grant(s), no delegation risks"
    return f"RISK ({len(findings)} finding(s)):\n- " + "\n- ".join(findings)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "analyze"):
        return f"ERROR: unknown op {args.get('op')!r}"
    grants = args.get("grants")
    if not isinstance(grants, list) or not grants:
        return "ERROR: grants (list of {from,to,capability}) is required"
    sensitive = {str(s).strip() for s in (args.get("sensitive") or []) if str(s).strip()}
    return _analyze(grants, sensitive)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["analyze"]},
        "grants": {
            "type": "array",
            "description": "Capability grants: {from, to, capability}",
            "items": {"type": "object"},
        },
        "sensitive": {
            "type": "array",
            "description": "Capability names to flag when held",
            "items": {"type": "string"},
        },
    },
    "required": ["grants"],
}


def capability_delegation_graph() -> Tool:
    return Tool(
        name="capability_delegation_graph",
        description=(
            "Build + analyze a capability delegation graph for governance "
            "risks: delegation cycles, over-broad fan-out, and holders of "
            "sensitive capabilities. op=analyze with 'grants' "
            "([{from,to,capability}]) and optional 'sensitive' list. Returns "
            "CLEAN or RISK with findings. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
