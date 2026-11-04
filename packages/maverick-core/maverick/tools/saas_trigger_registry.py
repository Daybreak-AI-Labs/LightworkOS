"""Generic SaaS-trigger registry helper.

Complements the existing ``saas_trigger`` tool (which verifies a single webhook
and routes one event). This one manages the *registry* of triggers: it validates
and de-duplicates a set of ``{source, event, goal}`` rules, and matches an
incoming ``(source, event)`` against them — supporting wildcard ``*`` on either
field. Pure, offline, stdlib only (json). No disk, no network.

ops:
  - register(triggers=[{source, event, goal}]) -> a validated, de-duplicated
    registry (JSON {triggers, count}). Identical rules collapse to one.
  - match(source, event, registry) -> the goal(s) whose source+event match,
    exact or via ``*`` wildcard (JSON array, de-duplicated, order-stable).
"""
from __future__ import annotations

import json
from typing import Any

from . import Tool


def _normalize(trigger: Any) -> dict[str, str] | None:
    """Coerce one trigger dict into {source, event, goal} of non-empty strings."""
    if not isinstance(trigger, dict):
        return None
    source = trigger.get("source")
    event = trigger.get("event")
    goal = trigger.get("goal")
    if not all(isinstance(v, str) and v.strip() for v in (source, event, goal)):
        return None
    return {"source": source.strip(), "event": event.strip(), "goal": goal.strip()}


def _register(args: dict[str, Any]) -> str:
    triggers = args.get("triggers")
    if not isinstance(triggers, list) or not triggers:
        return "ERROR: triggers (non-empty array of {source, event, goal}) is required"
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, str]] = []
    for t in triggers:
        norm = _normalize(t)
        if norm is None:
            return "ERROR: each trigger needs non-empty source, event and goal"
        sig = (norm["source"], norm["event"], norm["goal"])
        if sig in seen:
            continue  # de-duplicate identical rules
        seen.add(sig)
        out.append(norm)
    return json.dumps({"triggers": out, "count": len(out)}, sort_keys=True)


def _field_matches(pattern: str, value: str) -> bool:
    # Wildcard '*' matches anything; otherwise an exact (case-sensitive) compare.
    return pattern == "*" or pattern == value


def _match(args: dict[str, Any]) -> str:
    source = args.get("source")
    event = args.get("event")
    if not isinstance(source, str) or not source.strip():
        return "ERROR: source is required"
    if not isinstance(event, str) or not event.strip():
        return "ERROR: event is required"
    registry = args.get("registry")
    # Accept either the {"triggers": [...]} envelope (op=register output) or a
    # bare list of triggers.
    if isinstance(registry, dict):
        rules = registry.get("triggers")
    else:
        rules = registry
    if not isinstance(rules, list):
        return "ERROR: registry (an array, or {triggers:[...]}) is required"

    src = source.strip()
    evt = event.strip()
    goals: list[str] = []
    for r in rules:
        norm = _normalize(r)
        if norm is None:
            continue
        if _field_matches(norm["source"], src) and _field_matches(norm["event"], evt):
            if norm["goal"] not in goals:  # de-dupe goals, keep first-seen order
                goals.append(norm["goal"])
    return json.dumps(goals, sort_keys=True)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "register":
        return _register(args)
    if op == "match":
        return _match(args)
    return f"ERROR: unknown op {op!r} (expected register or match)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["register", "match"]},
        "triggers": {
            "type": "array",
            "description": "for op=register; each {source, event, goal}",
            "items": {
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "event": {"type": "string"},
                    "goal": {"type": "string"},
                },
                "required": ["source", "event", "goal"],
            },
        },
        "source": {"type": "string", "description": "incoming source for op=match"},
        "event": {"type": "string", "description": "incoming event for op=match"},
        "registry": {
            "description": "for op=match; a trigger array or {triggers:[...]} envelope",
        },
    },
    "required": ["op"],
}


def saas_trigger_registry() -> Tool:
    return Tool(
        name="saas_trigger_registry",
        description=(
            "SaaS-trigger registry helper (complements saas_trigger). "
            "op=register {triggers:[{source, event, goal}]} -> a validated, "
            "de-duplicated registry as JSON {triggers, count}. op=match {source, "
            "event, registry} -> the matching goal(s) as a JSON array (exact or "
            "'*' wildcard on either field). Pure stdlib json; offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
