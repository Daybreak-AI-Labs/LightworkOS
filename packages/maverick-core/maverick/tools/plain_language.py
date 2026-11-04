"""Plain-language explanation tool.

Narrate a plan/trace in plain English so a non-technical stakeholder can follow
what the agent intends to do: a numbered "First, I will … Then …" story that
maps known action verbs to friendly phrasing and falls back to a generic phrase
for anything unrecognised. Deterministic templating — no model call.

ops:
  - explain(steps)  — steps: list of {step?, action, args?}.
"""
from __future__ import annotations

from typing import Any

from . import Tool

# Known action verbs -> a friendly clause template. ``{target}`` is filled from
# the step's args (first sensible value) when present.
_PHRASES: dict[str, str] = {
    "read_file": "read the file {target}",
    "write_file": "write to the file {target}",
    "list_dir": "list the contents of {target}",
    "shell": "run the command {target}",
    "search": "search for {target}",
    "web_search": "search the web for {target}",
    "http_fetch": "fetch {target} from the web",
    "edit": "edit {target}",
    "delete": "delete {target}",
    "create": "create {target}",
    "test": "run the tests for {target}",
    "compute": "calculate {target}",
    "notify": "send a notification about {target}",
    "spawn_subagent": "delegate {target} to a helper agent",
}

_ORDINALS = ("First", "Then", "After that", "Next", "Then", "Finally")


def _target(args: Any) -> str:
    """Pull a human-meaningful target out of an args object/string."""
    if isinstance(args, str):
        return args.strip()
    if isinstance(args, dict):
        for key in ("path", "file", "query", "command", "url", "target", "name"):
            v = args.get(key)
            if isinstance(v, (str, int, float)) and str(v).strip():
                return str(v).strip()
    return ""


def _clause(action: str, args: Any) -> str:
    target = _target(args)
    verb = action.strip()
    template = _PHRASES.get(verb)
    if template is not None:
        if target:
            return template.format(target=target)
        # Drop the dangling "{target}" when no target was supplied.
        return template.split(" {target}")[0].replace("{target}", "").strip()
    # Unknown action: generic phrasing.
    if target:
        return f"perform '{verb}' on {target}"
    return f"perform the '{verb}' action"


def _explain(steps: list) -> str:
    clauses: list[str] = []
    for s in steps:
        if not isinstance(s, dict):
            continue
        action = str(s.get("action", "")).strip()
        if not action:
            continue
        clauses.append(_clause(action, s.get("args")))

    if not clauses:
        return "ERROR: no steps with an 'action' to explain"

    lines = []
    for i, clause in enumerate(clauses):
        lead = _ORDINALS[i] if i < len(_ORDINALS) else "Then"
        lines.append(f"{i + 1}. {lead}, I will {clause}.")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "explain"):
        return f"ERROR: unknown op {args.get('op')!r}"
    steps = args.get("steps")
    if not isinstance(steps, list) or not steps:
        return "ERROR: steps (non-empty list of {action, args?}) is required"
    return _explain(steps)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["explain"]},
        "steps": {
            "type": "array",
            "description": "plan/trace; each {step?, action, args?}",
            "items": {
                "type": "object",
                "properties": {
                    "step": {"description": "optional step identifier"},
                    "action": {"type": "string"},
                    "args": {"description": "string or object describing the target"},
                },
                "required": ["action"],
            },
        },
    },
    "required": ["steps"],
}


def plain_language() -> Tool:
    return Tool(
        name="plain_language",
        description=(
            "Narrate a plan/trace in plain English. op=explain with 'steps' "
            "(each {step?, action, args?}). Renders a numbered 'First, I will "
            "… Then …' story, mapping known action verbs to friendly phrasing "
            "and falling back to a generic phrase for unknown actions. "
            "Deterministic, no model."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
