"""Every registered tool's input_schema must be valid JSON Schema draft
2020-12.

The Anthropic Messages API validates each tool's ``input_schema`` against
draft 2020-12 and rejects the WHOLE request with a 400 if any single tool is
invalid. Because the full tool catalog is sent on every agent LLM call, one
malformed schema makes every ``maverick start`` / ``maverick chat`` run crash
at the first call with::

    tools.N.custom.input_schema: JSON schema is invalid. It must match
    JSON Schema draft 2020-12.

Regression: ``mongodb``'s ``sort`` schema used draft-07 tuple syntax
(``"items": [<schema>, <schema>]``). In draft 2020-12 the array form of
``items`` was renamed ``prefixItems``; ``items`` must be a single schema, so an
array there fails validation ("is not of type 'object', 'boolean'").

This test walks every base-registry tool schema for the draft-07 -> 2020-12
migration traps that pass a casual eye but the API rejects. It needs no network
and no extra dependency.
"""
from __future__ import annotations

from pathlib import Path

from maverick.sandbox import LocalBackend
from maverick.tools import base_registry
from maverick.world_model import WorldModel


def _draft202012_violations(node: object, path: str):
    """Yield (location, reason) for draft-07-isms the Anthropic API rejects."""
    if isinstance(node, dict):
        if isinstance(node.get("items"), list):
            yield (
                f"{path}.items",
                "array-form `items` is draft-07 tuple syntax; use `prefixItems`",
            )
        if "additionalItems" in node:
            yield (f"{path}.additionalItems", "`additionalItems` was removed in 2020-12")
        for kw in ("exclusiveMinimum", "exclusiveMaximum"):
            if isinstance(node.get(kw), bool):
                yield (f"{path}.{kw}", f"`{kw}` must be a number in 2020-12, not a bool")
        for key, value in node.items():
            yield from _draft202012_violations(value, f"{path}.{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _draft202012_violations(value, f"{path}[{i}]")


def test_all_base_tool_schemas_are_draft202012_valid(tmp_path: Path) -> None:
    world = WorldModel(tmp_path / "world.db")
    reg = base_registry(world, LocalBackend(workdir=str(tmp_path)))
    problems: list[str] = []
    for tool in reg.to_anthropic():
        for loc, reason in _draft202012_violations(tool["input_schema"], tool["name"]):
            problems.append(f"  {loc}: {reason}")
    assert not problems, (
        "tool input_schema(s) violate JSON Schema draft 2020-12 -- the Anthropic "
        "API will 400 the entire request:\n" + "\n".join(problems)
    )
