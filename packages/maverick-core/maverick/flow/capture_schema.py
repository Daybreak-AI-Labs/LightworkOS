"""Suggest the data description a learning-example capture needs.

Enrolling a run as a learning example (``ActionEpisodeReviewService.enroll``)
requires complete, bounded descriptions of the run's inputs and of every
allowed tool's arguments and result, in the closed schema language the
capture service admits. People should never write those by hand, so this
suggests them from real data the owner can already see:

* inputs from the run's own starting data;
* each tool's arguments from the step's parameters (a parameter copied from an
  input takes that input's description, a fixed value its own);
* each tool's result from what the same step returned in an earlier finished
  run of the flow, when there is one;
* anything the owner described for an earlier example of this flow wins.

Suggestions are only a starting point: the page shows them as plain fields
the person can change, and the capture service validates the final contract
and every captured value against it. Nothing here stores or sends data.
"""
from __future__ import annotations

import copy
import json
import re

MAX_TEXT = 1024
MAX_NUMBER = 10**12
MAX_DEPTH = 6
MAX_FIELDS = 64
_INPUT_REF = re.compile(r"^\{\{\s*input\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$")


def describe(value, *, depth: int = 0) -> dict:
    """A closed, bounded description matching ``value``."""
    if depth > MAX_DEPTH:
        raise ValueError("value is nested too deeply to describe")
    if value is None:
        return {"type": "null"}
    if type(value) is bool:
        return {"type": "boolean"}
    if type(value) is int:
        bound = max(MAX_NUMBER, abs(value))
        return {"type": "integer", "minimum": -bound, "maximum": bound}
    if type(value) is float:
        bound = max(float(MAX_NUMBER), abs(value))
        return {"type": "number", "minimum": -bound, "maximum": bound}
    if type(value) is str:
        return {"type": "string", "maxLength": MAX_TEXT}
    if type(value) is list:
        if len(value) > 64:
            raise ValueError("list is too long to describe")
        item = describe(value[0], depth=depth + 1) if value else {"type": "null"}
        return {"type": "array", "items": item, "minItems": len(value), "maxItems": len(value)}
    if type(value) is dict:
        if len(value) > MAX_FIELDS:
            raise ValueError("too many fields to describe")
        props = {str(key): describe(child, depth=depth + 1) for key, child in value.items()}
        return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}
    raise ValueError("value cannot be described")


def _object(schema) -> dict:
    return schema if isinstance(schema, dict) and schema.get("type") == "object" else {
        "type": "object", "properties": {}, "required": [], "additionalProperties": False}


def _parse(result):
    if isinstance(result, str):
        try:
            return json.loads(result)
        except ValueError:
            return None
    return result


def _arguments(params: dict, inputs: dict, input_schema: dict) -> dict:
    props = {}
    for key, raw in (params or {}).items():
        if isinstance(raw, str):
            ref = _INPUT_REF.match(raw)
            if ref and ref.group(1) in inputs:
                props[str(key)] = copy.deepcopy(input_schema["properties"][ref.group(1)])
                continue
            if "{{" in raw:
                props[str(key)] = {"type": "string", "maxLength": MAX_TEXT}
                continue
        props[str(key)] = describe(raw, depth=1)
    return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}


def suggest_contract(flow, run, *, allowed_tools, prior_contract: dict | None = None,
                     earlier_runs=()) -> dict:
    """``{"input_schema", "tool_data_schemas", "unknown_results"}`` for enrolling ``run``."""
    raw_inputs = run.input_data.get("input", run.input_data) if isinstance(run.input_data, dict) else {}
    inputs = raw_inputs if isinstance(raw_inputs, dict) else {}
    input_schema = _object(describe(inputs))
    prior = prior_contract.get("tool_data_schemas", {}) if isinstance(prior_contract, dict) else {}
    tools: dict[str, dict] = {}
    unknown: list[str] = []
    for node in flow.nodes.values():
        if node.kind != "action" or node.tool not in allowed_tools or node.tool in tools:
            continue
        if node.tool in prior:
            tools[node.tool] = copy.deepcopy(prior[node.tool])
            continue
        result = None
        for earlier in earlier_runs:
            value = _parse((earlier.data or {}).get(node.output)) if node.output else None
            if isinstance(value, dict):
                result = describe(value)
                break
        if result is None:
            unknown.append(node.tool)
            result = _object(None)
        tools[node.tool] = {"arguments": _arguments(node.params, inputs, input_schema), "result": result}
    return {"input_schema": input_schema, "tool_data_schemas": tools, "unknown_results": sorted(unknown)}


__all__ = ["describe", "suggest_contract"]
