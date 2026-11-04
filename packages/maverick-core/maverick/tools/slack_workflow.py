"""Slack workflow integration.

Build the JSON for a Slack Workflow custom step — the function definition you
register so a Lightwork goal can appear as a step in Workflow Builder — and the
payload that invokes that step's trigger. This constructs and validates the JSON
offline; calling the Slack API is a separate step (http_fetch). Deterministic;
offline; pure stdlib (json). No disk, no network.

ops:
  - build_step(name, inputs={key: {type}}, outputs=[{name, type}], callback_id?)
    -> the custom-step (function) definition JSON.
  - trigger_payload(callback_id, values={...}) -> the trigger invocation payload.

Slack workflow value types (a useful subset): string, number, boolean, integer,
user, channel, timestamp, slack#/types/* . The type is recorded verbatim.
"""
from __future__ import annotations

import json
import re
from typing import Any

from . import Tool

# Slack callback_id / input key convention: lowercase, digits, underscores.
_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,49}$")


def _input_props(inputs: Any) -> dict[str, Any] | str:
    if not isinstance(inputs, dict) or not inputs:
        return "ERROR: inputs ({key: {type}}) is required"
    props: dict[str, Any] = {}
    for key, spec in inputs.items():
        name = str(key)
        if not _KEY_RE.match(name):
            return f"ERROR: input key {name!r} must match ^[a-z][a-z0-9_]*$"
        if not isinstance(spec, dict):
            return f"ERROR: input {name!r} must be an object {{type}}"
        itype = str(spec.get("type") or "").strip()
        if not itype:
            return f"ERROR: input {name!r} missing type"
        props[name] = {"type": itype}
    return props


def _output_props(outputs: Any) -> dict[str, Any] | str:
    if not isinstance(outputs, list):
        return "ERROR: outputs must be an array of {name, type}"
    props: dict[str, Any] = {}
    for spec in outputs:
        if not isinstance(spec, dict):
            return "ERROR: each output must be an object {name, type}"
        name = str(spec.get("name") or "").strip()
        otype = str(spec.get("type") or "").strip()
        if not _KEY_RE.match(name):
            return f"ERROR: output name {name!r} must match ^[a-z][a-z0-9_]*$"
        if not otype:
            return f"ERROR: output {name!r} missing type"
        props[name] = {"type": otype}
    return props


def _build_step(args: dict[str, Any]) -> str:
    name = str(args.get("name") or "").strip()
    if not name:
        return "ERROR: name is required"
    callback_id = str(args.get("callback_id") or "").strip()
    if callback_id and not _KEY_RE.match(callback_id):
        return f"ERROR: callback_id {callback_id!r} must match ^[a-z][a-z0-9_]*$"
    if not callback_id:
        # Derive a stable callback_id from the name.
        callback_id = re.sub(r"[^a-z0-9_]+", "_", name.lower()).strip("_") or "step"
        # A derived id must satisfy the same ^[a-z][a-z0-9_]* rule enforced on
        # an explicit callback_id: a name like "2027 report" would otherwise
        # yield "2027_report" (starts with a digit), which Slack's Workflow
        # Builder rejects. Prefix a letter so derived ids are always valid.
        if not _KEY_RE.match(callback_id):
            callback_id = "s_" + callback_id

    input_props = _input_props(args.get("inputs"))
    if isinstance(input_props, str):
        return input_props
    output_props = _output_props(args.get("outputs", []))
    if isinstance(output_props, str):
        return output_props

    definition = {
        "callback_id": callback_id,
        "title": name,
        "input_parameters": {
            "properties": input_props,
            "required": sorted(input_props.keys()),
        },
        "output_parameters": {
            "properties": output_props,
            "required": sorted(output_props.keys()),
        },
    }
    return json.dumps(definition, sort_keys=True)


def _trigger_payload(args: dict[str, Any]) -> str:
    callback_id = str(args.get("callback_id") or "").strip()
    if not callback_id:
        return "ERROR: callback_id is required"
    values = args.get("values")
    if not isinstance(values, dict):
        return "ERROR: values (object) is required"
    payload = {
        "type": "workflow_step_execute",
        "callback_id": callback_id,
        "inputs": {str(k): {"value": v} for k, v in values.items()},
    }
    return json.dumps(payload, sort_keys=True)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "build_step":
        return _build_step(args)
    if op == "trigger_payload":
        return _trigger_payload(args)
    return f"ERROR: unknown op {op!r} (expected build_step or trigger_payload)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["build_step", "trigger_payload"]},
        "name": {"type": "string", "description": "step title for op=build_step"},
        "inputs": {
            "type": "object",
            "description": "for op=build_step; {key: {type}}",
            "additionalProperties": {
                "type": "object",
                "properties": {"type": {"type": "string"}},
            },
        },
        "outputs": {
            "type": "array",
            "description": "for op=build_step; each {name, type}",
            "items": {
                "type": "object",
                "properties": {"name": {"type": "string"}, "type": {"type": "string"}},
            },
        },
        "callback_id": {"type": "string", "description": "custom-step id (derived from name if omitted)"},
        "values": {
            "type": "object",
            "description": "for op=trigger_payload; {input_key: value}",
        },
    },
    "required": ["op"],
}


def slack_workflow() -> Tool:
    return Tool(
        name="slack_workflow",
        description=(
            "Build Slack workflow custom-step JSON (does not send). "
            "op=build_step {name, inputs:{key:{type}}, outputs:[{name, type}], "
            "callback_id?} -> the function definition. op=trigger_payload "
            "{callback_id, values:{key: value}} -> the step invocation payload. "
            "Returns json.dumps. Deterministic; offline; stdlib json only."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
