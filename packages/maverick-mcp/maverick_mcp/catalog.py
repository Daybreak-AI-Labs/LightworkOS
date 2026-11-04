"""Validated protocol tool declarations shared across MCP transports."""
from __future__ import annotations

import json
import re
from typing import Any, TypedDict


class ToolSpec(TypedDict, total=False):
    """Typed MCP tool declaration; runtime validation enforces required keys."""

    name: str
    description: str
    inputSchema: dict[str, Any]
    outputSchema: dict[str, Any]
    execution: dict[str, str]


TOOLS: list[ToolSpec] = [
    {
        "name": "maverick_start",
        "description": (
            "Start a new goal in Lightwork's recursive multi-agent swarm. "
            "Returns the final answer after the swarm completes. Long-running."
        ),
        # Long-running, so it supports task augmentation (run async, poll for
        # the result) where the client and transport (stdio) allow it.
        "execution": {"taskSupport": "optional"},
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "description": {"type": "string"},
                "max_dollars": {"type": "number", "minimum": 0},
                "max_wall_seconds": {"type": "number", "minimum": 0},
                "max_depth": {"type": "integer", "default": 3},
            },
            "required": ["title"],
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "goal_id": {"type": "integer"},
                "answer": {"type": "string"},
            },
            "required": ["goal_id", "answer"],
        },
    },
    {
        "name": "maverick_status",
        "description": "List recent goals and any open questions.",
        "inputSchema": {"type": "object", "properties": {}},
        "outputSchema": {
            "type": "object",
            "properties": {
                "goals": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "status": {"type": "string"},
                            "title": {"type": "string"},
                        },
                    },
                },
                "open_questions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "goal_id": {"type": "integer"},
                            "question": {"type": "string"},
                        },
                    },
                },
            },
            "required": ["goals", "open_questions"],
        },
    },
    {
        "name": "maverick_resume",
        "description": "Resume a paused goal by id.",
        "execution": {"taskSupport": "optional"},
        "inputSchema": {
            "type": "object",
            "properties": {"goal_id": {"type": "integer"}},
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "goal_id": {"type": "integer"},
                "answer": {"type": "string"},
            },
            "required": ["goal_id", "answer"],
        },
    },
    {
        "name": "maverick_answer",
        "description": "Answer a queued question.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "question_id": {"type": "integer"},
                "answer": {"type": "string"},
            },
            "required": ["question_id", "answer"],
        },
        "outputSchema": {
            "type": "object",
            "properties": {"question_id": {"type": "integer"}},
            "required": ["question_id"],
        },
    },
    {
        "name": "maverick_skill_install",
        "description": "Install a SKILL.md from a URL or gh:org/repo[:path].",
        "inputSchema": {
            "type": "object",
            "properties": {"source": {"type": "string"}},
            "required": ["source"],
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "path": {"type": "string"},
            },
            "required": ["name", "path"],
        },
    },
    {
        "name": "maverick_skills_list",
        "description": "List installed / distilled skills.",
        "inputSchema": {"type": "object", "properties": {}},
        "outputSchema": {
            "type": "object",
            "properties": {
                "skills": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "triggers": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                },
            },
            "required": ["skills"],
        },
    },
    {
        "name": "maverick_fact_set",
        "description": "Store a fact in the persistent world model.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "value": {"type": "string"},
            },
            "required": ["key", "value"],
        },
        "outputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "maverick_fleet_ingest",
        "description": (
            "Deposit experience from an EXTERNAL agent into Lightwork's "
            "governed fleet memory (Learning System of Record). The agent "
            "must be on the fleet roster; records are Shield-scanned, "
            "provenance-tagged, and audited. Requires [fleet_memory] enable."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "vendor": {"type": "string"},
                "kind": {"type": "string", "enum": ["success", "failure", "lesson"]},
                "goal_text": {"type": "string"},
                "reflection": {"type": "string"},
                "domain": {"type": "string"},
            },
            "required": ["agent_id", "vendor", "kind", "goal_text"],
        },
        "outputSchema": {
            "type": "object",
            "properties": {"ok": {"type": "boolean"}, "reason": {"type": "string"}},
            "required": ["ok", "reason"],
        },
    },
    {
        "name": "maverick_fleet_recall",
        "description": (
            "Governed memory read for an EXTERNAL fleet agent: department-"
            "boosted lessons + consolidated insights for a task. Every read "
            "is audited with the reader's identity."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "vendor": {"type": "string"},
                "query": {"type": "string"},
                "domain": {"type": "string"},
            },
            "required": ["agent_id", "vendor", "query"],
        },
        "outputSchema": {
            "type": "object",
            "properties": {"context": {"type": "string"}, "reason": {"type": "string"}},
            "required": ["reason"],
        },
    },
    {
        "name": "maverick_facts_get",
        "description": "Get all known facts.",
        "inputSchema": {"type": "object", "properties": {}},
        "outputSchema": {
            "type": "object",
            "properties": {
                "facts": {"type": "object", "additionalProperties": {"type": "string"}},
            },
            "required": ["facts"],
        },
    },
]

_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_TOOL_SPEC_KEYS = frozenset(
    {"name", "description", "inputSchema", "outputSchema", "execution"}
)


def _validate_tool_specs(specs: list[ToolSpec]) -> dict[str, ToolSpec]:
    """Validate the catalog once and return its immutable-name lookup."""
    by_name: dict[str, ToolSpec] = {}
    for index, spec in enumerate(specs):
        if not isinstance(spec, dict):
            raise RuntimeError(f"MCP tool declaration {index} must be an object")
        unknown = set(spec) - _TOOL_SPEC_KEYS
        if unknown:
            raise RuntimeError(
                f"MCP tool declaration {index} has unknown fields: "
                f"{sorted(unknown)}"
            )
        name = spec.get("name")
        description = spec.get("description")
        input_schema = spec.get("inputSchema")
        output_schema = spec.get("outputSchema")
        if not isinstance(name, str) or not _TOOL_NAME_RE.fullmatch(name):
            raise RuntimeError(f"MCP tool declaration {index} has an invalid name")
        if name in by_name:
            raise RuntimeError(f"duplicate MCP tool declaration: {name}")
        if not isinstance(description, str) or not description.strip():
            raise RuntimeError(f"MCP tool {name} has no description")
        for label, schema in (
            ("inputSchema", input_schema),
            ("outputSchema", output_schema),
        ):
            if (
                not isinstance(schema, dict)
                or schema.get("type") != "object"
                or not isinstance(schema.get("properties"), dict)
            ):
                raise RuntimeError(
                    f"MCP tool {name} has an invalid {label} object schema"
                )
            required = schema.get("required", [])
            if (
                not isinstance(required, list)
                or any(not isinstance(field, str) for field in required)
                or not set(required).issubset(schema["properties"])
            ):
                raise RuntimeError(
                    f"MCP tool {name} has invalid {label}.required fields"
                )
        execution = spec.get("execution")
        if execution is not None and (
            not isinstance(execution, dict)
            or set(execution) != {"taskSupport"}
            or execution.get("taskSupport") not in {"optional", "required"}
        ):
            raise RuntimeError(f"MCP tool {name} has invalid execution metadata")
        try:
            json.dumps(spec, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"MCP tool {name} is not canonical JSON") from exc
        by_name[name] = spec
    if not by_name:
        raise RuntimeError("MCP tool catalog must not be empty")
    return by_name


_TOOL_BY_NAME = _validate_tool_specs(TOOLS)
_TOOL_NAMES = frozenset(_TOOL_BY_NAME)
