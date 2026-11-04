"""AutoGen adapter.

Pure, offline schema translation between Lightwork tools and Microsoft AutoGen's
function/tool spec shape. No SDK import, no network — this just reshapes dicts so
a Lightwork tool can be handed to an AutoGen agent and vice-versa.

AutoGen describes a callable tool as a function spec::

    {"type": "function",
     "function": {"name": ..., "description": ..., "parameters": <json-schema>}}

ops:
  - tool_spec(name, description, params_schema) -> the AutoGen function spec
    (JSON string), wrapping a JSON-Schema object of parameters.
  - from_autogen(spec) -> Lightwork's {name, description, input_schema} (JSON),
    accepting either the wrapped {"function": {...}} form or a bare function dict.
"""
from __future__ import annotations

import json
from typing import Any

from . import Tool

# Default empty JSON-Schema object so an AutoGen consumer always sees a valid
# parameters shape even when a tool takes no arguments.
_EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}


def _tool_spec(args: dict[str, Any]) -> str:
    name = args.get("name")
    description = args.get("description")
    if not isinstance(name, str) or not name.strip():
        return "ERROR: name is required"
    if not isinstance(description, str) or not description.strip():
        return "ERROR: description is required"
    params = args.get("params_schema")
    if params is None:
        params = dict(_EMPTY_SCHEMA)
    if not isinstance(params, dict):
        return "ERROR: params_schema must be a JSON-Schema object"
    # AutoGen expects an object-typed parameter schema; default the type so a
    # caller can pass just {"properties": {...}}.
    params = dict(params)
    params.setdefault("type", "object")
    spec = {
        "type": "function",
        "function": {
            "name": name.strip(),
            "description": description.strip(),
            "parameters": params,
        },
    }
    return json.dumps(spec, sort_keys=True)


def _from_autogen(args: dict[str, Any]) -> str:
    spec = args.get("spec")
    if not isinstance(spec, dict) or not spec:
        return "ERROR: spec (an AutoGen tool/function dict) is required"
    # Accept the wrapped {"type":"function","function":{...}} form or a bare
    # function dict {"name":..., "parameters":...}.
    fn = spec.get("function") if isinstance(spec.get("function"), dict) else spec
    name = fn.get("name")
    if not isinstance(name, str) or not name.strip():
        return "ERROR: spec has no function name"
    description = fn.get("description")
    description = description.strip() if isinstance(description, str) else ""
    params = fn.get("parameters")
    if not isinstance(params, dict):
        params = dict(_EMPTY_SCHEMA)
    out = {
        "name": name.strip(),
        "description": description,
        "input_schema": params,
    }
    return json.dumps(out, sort_keys=True)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "tool_spec":
        return _tool_spec(args)
    if op == "from_autogen":
        return _from_autogen(args)
    return f"ERROR: unknown op {op!r} (expected tool_spec or from_autogen)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["tool_spec", "from_autogen"]},
        "name": {"type": "string", "description": "tool name for op=tool_spec"},
        "description": {"type": "string", "description": "tool description for op=tool_spec"},
        "params_schema": {
            "type": "object",
            "description": "JSON-Schema of the tool's parameters for op=tool_spec",
        },
        "spec": {
            "type": "object",
            "description": "an AutoGen function/tool spec for op=from_autogen",
        },
    },
    "required": ["op"],
}


def autogen_adapter() -> Tool:
    return Tool(
        name="autogen_adapter",
        description=(
            "Microsoft AutoGen interop (schema only). op=tool_spec {name, "
            "description, params_schema} -> an AutoGen function spec "
            "{type:function, function:{name, description, parameters}} as JSON. "
            "op=from_autogen {spec} -> Lightwork's {name, description, "
            "input_schema} as JSON (accepts wrapped or bare function dicts). "
            "Pure stdlib translation; no SDK, no network."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
