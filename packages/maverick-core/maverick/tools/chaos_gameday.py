"""Chaos game-day script generator.

Turn a service dependency graph into an ordered fault-injection plan for a chaos
game-day. Deterministic and offline: the caller supplies the components (each
``{name, deps: [...]}`` where ``deps`` are the components it depends on) and a
fault type (``kill`` / ``latency`` / ``netsplit``); this resolves the plan.

Ordering is topological by dependency: a component is faulted only after the
components it depends on, so blast radius grows predictably from the most
upstream services outward. Ties (and any dependency cycle, which is reported but
not fatal) break by name for determinism.

Blast radius of a step = the transitive set of components that depend on the
faulted component (its downstream dependents) — who you should expect to see
degrade when that fault fires.

ops:
  - plan(components, fault)  — ordered steps with blast-radius + a rollback note.
"""
from __future__ import annotations

from typing import Any

from . import Tool

_FAULTS = {
    "kill": "terminate the process/instance",
    "latency": "inject artificial latency",
    "netsplit": "partition the network to/from the component",
}

# Per-fault rollback note.
_ROLLBACKS = {
    "kill": "restart/redeploy the component and confirm it rejoins the pool",
    "latency": "remove the latency injection (tc/proxy rule) and verify p99 recovers",
    "netsplit": "heal the partition (restore firewall/route rules) and verify reconnection",
}


def _topo_order(names: list[str], deps: dict[str, list[str]]) -> tuple[list[str], list[str]]:
    """Kahn topological sort (dependencies first). Returns (order, cyclic).

    Edge dep -> node means dep must come first. Ties resolved by name so the
    plan is deterministic. Any nodes left in a cycle are appended (sorted) and
    also returned as ``cyclic`` so the caller can note them.
    """
    # indegree[n] = number of this-node's deps still unplaced.
    indeg = dict.fromkeys(names, 0)
    dependents: dict[str, list[str]] = {n: [] for n in names}
    for n in names:
        for d in deps[n]:
            if d in indeg:
                indeg[n] += 1
                dependents[d].append(n)

    ready = sorted([n for n in names if indeg[n] == 0])
    order: list[str] = []
    while ready:
        n = ready.pop(0)
        order.append(n)
        newly: list[str] = []
        for m in dependents[n]:
            indeg[m] -= 1
            if indeg[m] == 0:
                newly.append(m)
        if newly:
            ready = sorted(ready + newly)

    cyclic = sorted(n for n in names if n not in order)
    order.extend(cyclic)  # keep cyclic nodes in the plan, just flagged
    return order, cyclic


def _downstream(start: str, dependents: dict[str, set[str]]) -> list[str]:
    """Transitive set of components that depend on ``start`` (its blast radius)."""
    seen: set[str] = set()
    stack = list(dependents.get(start, set()))
    while stack:
        cur = stack.pop()
        if cur in seen or cur == start:
            continue
        seen.add(cur)
        stack.extend(dependents.get(cur, set()))
    return sorted(seen)


def _plan(components: list, fault: str) -> str:
    fault = fault.strip().lower()
    if fault not in _FAULTS:
        return f"ERROR: fault must be one of {sorted(_FAULTS)}"

    names: list[str] = []
    deps: dict[str, list[str]] = {}
    for i, c in enumerate(components):
        if not isinstance(c, dict):
            return f"ERROR: component #{i} must be an object"
        name = c.get("name")
        if not isinstance(name, str) or not name.strip():
            return f"ERROR: component #{i} needs a non-empty name"
        if name in deps:
            return f"ERROR: duplicate component name {name!r}"
        raw_deps = c.get("deps", [])
        if not isinstance(raw_deps, list):
            return f"ERROR: component {name!r} deps must be a list"
        names.append(name)
        deps[name] = [str(d) for d in raw_deps]

    # dependents[d] = set of nodes that directly depend on d.
    dependents: dict[str, set[str]] = {n: set() for n in names}
    for n in names:
        for d in deps[n]:
            if d in dependents:
                dependents[d].add(n)

    order, cyclic = _topo_order(names, deps)

    lines: list[str] = []
    for step, name in enumerate(order, start=1):
        blast = _downstream(name, dependents)
        radius = ", ".join(blast) if blast else "(none — leaf-facing)"
        lines.append(
            f"  {step}. {fault} {name} ({_FAULTS[fault]}); "
            f"blast_radius=[{radius}]"
        )

    header = f"PLAN fault={fault} steps={len(order)} components={len(names)}"
    if cyclic:
        header += f" (cycle detected among: {', '.join(cyclic)})"
    rollback = f"  rollback: {_ROLLBACKS[fault]} (reverse step order)"
    return header + "\n" + "\n".join(lines) + "\n" + rollback


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "plan"):
        return f"ERROR: unknown op {args.get('op')!r}"
    components = args.get("components")
    if not isinstance(components, list) or not components:
        return "ERROR: components (non-empty list of {name, deps:[...]}) is required"
    fault = args.get("fault")
    if not isinstance(fault, str) or not fault.strip():
        return "ERROR: fault (kill | latency | netsplit) is required"
    return _plan(components, fault)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["plan"]},
        "components": {
            "type": "array",
            "description": "Components: {name, deps:[...]} (deps = what it depends on)",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "deps": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["name"],
            },
        },
        "fault": {
            "type": "string",
            "enum": ["kill", "latency", "netsplit"],
            "description": "Fault type to inject",
        },
    },
    "required": ["components", "fault"],
}


def chaos_gameday() -> Tool:
    return Tool(
        name="chaos_gameday",
        description=(
            "Chaos game-day script generator. op=plan with 'components' (each "
            "{name, deps:[...]}) and a 'fault' (kill | latency | netsplit). "
            "Produces a topologically ordered fault-injection plan (dependencies "
            "first), each step's blast radius (transitive downstream dependents), "
            "and a rollback note. Reports any dependency cycle without failing. "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
