"""Project an authorized live registry into workflow-authoring metadata."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def project_tools(live: Iterable[Any]) -> tuple[list[dict], dict[str, dict]]:
    """Return public picker entries and private input contracts separately."""
    from maverick.flow.ir import action_tool_policy_error

    from .tool_categories import categorize

    index: list[dict] = []
    schemas: dict[str, dict] = {}
    for tool in live:
        if action_tool_policy_error(tool.name):
            continue
        params = []
        if isinstance(tool.input_schema, dict):
            params = list((tool.input_schema.get("properties") or {}).keys())[:12]
            schemas[tool.name] = dict(tool.input_schema)
        description = (tool.description or "")[:200]
        index.append({
            "name": tool.name,
            "description": description,
            "params": params,
            "category": categorize(tool.name, description),
        })
    return index, schemas
