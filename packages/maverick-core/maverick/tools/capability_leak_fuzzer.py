"""Capability-leak fuzzer.

Given the set of capabilities currently *granted* and a tool→required-capability
map, enumerate every tool and report capability LEAKS — tools that would run
without holding a capability they require — and OVER-GRANTS — capabilities held
but never required by any listed tool. Deterministic enumeration (not random
sampling): each tool is probed exactly once against the granted set, so the same
inputs always yield the same report.

ops:
  - fuzz(granted, tools)  — leaks + over-grants + a PASS/FAIL summary.

``granted`` is a list of capability strings. ``tools`` is a list of
``{tool, requires}`` where ``requires`` is a string or list of capability
strings. A tool with no requirements never leaks.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _as_caps(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        cap = value.strip()
        return [cap] if cap else []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def _fuzz(granted: list[str], tools: list[dict]) -> str:
    held = {c.strip() for c in granted if str(c).strip()}
    required_anywhere: set[str] = set()
    leaks: list[str] = []

    for entry in tools:
        if not isinstance(entry, dict):
            return "ERROR: each tools[] entry must be an object {tool, requires}"
        name = str(entry.get("tool") or "").strip()
        if not name:
            return "ERROR: each tools[] entry needs a non-empty 'tool'"
        reqs = _as_caps(entry.get("requires"))
        required_anywhere.update(reqs)
        missing = [c for c in reqs if c not in held]
        if missing:
            leaks.append(f"{name}: runs WITHOUT required {sorted(set(missing))}")

    over = sorted(held - required_anywhere)

    lines = [f"probed {len(tools)} tool(s) against {len(held)} granted capability(ies)"]
    if leaks:
        lines.append(f"LEAKS ({len(leaks)}):")
        lines.extend(f"- {leak}" for leak in leaks)
    else:
        lines.append("LEAKS: none")
    if over:
        lines.append(f"OVER-GRANTS ({len(over)}): {over} held but never required")
    else:
        lines.append("OVER-GRANTS: none")
    lines.append("result: " + ("FAIL — capability leak detected" if leaks else "PASS"))
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "fuzz"):
        return f"ERROR: unknown op {args.get('op')!r} (expected fuzz)"
    granted = args.get("granted")
    tools = args.get("tools")
    if not isinstance(granted, list):
        return "ERROR: granted (array of capability strings) is required"
    if not isinstance(tools, list):
        return "ERROR: tools (array of {tool, requires}) is required"
    return _fuzz(granted, tools)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["fuzz"]},
        "granted": {
            "type": "array",
            "items": {"type": "string"},
            "description": "capabilities currently granted",
        },
        "tools": {
            "type": "array",
            "description": "tools to probe; each {tool, requires}",
            "items": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string"},
                    "requires": {
                        "description": "capability string or list of strings",
                        "type": ["string", "array"],
                        "items": {"type": "string"},
                    },
                },
                "required": ["tool"],
            },
        },
    },
    "required": ["granted", "tools"],
}


def capability_leak_fuzzer() -> Tool:
    return Tool(
        name="capability_leak_fuzzer",
        description=(
            "Probe a capability grant set for leaks. op=fuzz with 'granted' "
            "(capability strings) and 'tools' (each {tool, requires}). "
            "Deterministically enumerates every tool and reports LEAKS (a tool "
            "that would run without a required capability) and OVER-GRANTS "
            "(capabilities held but never required), plus a PASS/FAIL summary. "
            "Pure, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
