"""CrewAI adapter.

Pure, offline translation between a CrewAI ``Task`` and a Lightwork goal. No SDK
import, no network — just dict/string reshaping so a CrewAI task can drive a
Lightwork run and vice-versa.

CrewAI describes a unit of work as a Task::

    {"description": ..., "expected_output": ..., "agent": <role>}

ops:
  - task_spec(description, expected_output, agent_role) -> a CrewAI Task spec
    dict (JSON string).
  - to_maverick_goal(task_spec) -> a Lightwork goal string + metadata (JSON
    {goal, metadata}). The goal folds in the expected output as an acceptance
    criterion so the swarm knows when it's done.
"""
from __future__ import annotations

import json
from typing import Any

from . import Tool


def _task_spec(args: dict[str, Any]) -> str:
    description = args.get("description")
    if not isinstance(description, str) or not description.strip():
        return "ERROR: description is required"
    expected = args.get("expected_output")
    if not isinstance(expected, str) or not expected.strip():
        return "ERROR: expected_output is required"
    role = args.get("agent_role")
    if not isinstance(role, str) or not role.strip():
        return "ERROR: agent_role is required"
    spec = {
        "description": description.strip(),
        "expected_output": expected.strip(),
        "agent": role.strip(),
    }
    return json.dumps(spec, sort_keys=True)


def _to_maverick_goal(args: dict[str, Any]) -> str:
    spec = args.get("task_spec")
    if not isinstance(spec, dict) or not spec:
        return "ERROR: task_spec (a CrewAI Task dict) is required"
    description = spec.get("description")
    if not isinstance(description, str) or not description.strip():
        return "ERROR: task_spec.description is required"
    description = description.strip()
    expected = spec.get("expected_output")
    expected = expected.strip() if isinstance(expected, str) else ""
    # CrewAI uses "agent" for the assigned role; accept "agent_role" too.
    role = spec.get("agent")
    if not isinstance(role, str) or not role.strip():
        role = spec.get("agent_role")
    role = role.strip() if isinstance(role, str) else ""

    goal = description
    if expected:
        goal = f"{description}\n\nAcceptance criteria: {expected}"
    out = {
        "goal": goal,
        "metadata": {
            "source": "crewai",
            "agent_role": role,
            "expected_output": expected,
        },
    }
    return json.dumps(out, sort_keys=True)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "task_spec":
        return _task_spec(args)
    if op == "to_maverick_goal":
        return _to_maverick_goal(args)
    return f"ERROR: unknown op {op!r} (expected task_spec or to_maverick_goal)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["task_spec", "to_maverick_goal"]},
        "description": {"type": "string", "description": "task description for op=task_spec"},
        "expected_output": {
            "type": "string",
            "description": "expected output / done-definition for op=task_spec",
        },
        "agent_role": {"type": "string", "description": "assigned agent role for op=task_spec"},
        "task_spec": {
            "type": "object",
            "description": "a CrewAI Task dict for op=to_maverick_goal",
        },
    },
    "required": ["op"],
}


def crewai_adapter() -> Tool:
    return Tool(
        name="crewai_adapter",
        description=(
            "CrewAI interop (translation only). op=task_spec {description, "
            "expected_output, agent_role} -> a CrewAI Task dict {description, "
            "expected_output, agent} as JSON. op=to_maverick_goal {task_spec} -> "
            "{goal, metadata} as JSON, folding expected_output into the goal as "
            "acceptance criteria. Pure stdlib; no SDK, no network."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
