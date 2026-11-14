"""Actual plugin-kind adapters, executed only inside the reviewed container.

The host also imports :func:`validator`/:func:`validate` to check practice
input against a schema the container reported, so the schema gate must not let
that schema make the host fetch anything. Channel checks invoke the real lifecycle
and send contract; the immutable image must supply synthetic local configuration.
Network denial is enforced by the container, never by a monkeypatched client.
"""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json


def validator(schema):
    from jsonschema import Draft202012Validator, FormatChecker

    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise ValueError("input schema must declare an object")
    Draft202012Validator.check_schema(schema)
    def refs(value):
        if isinstance(value, dict):
            # Every reference keyword resolves through the default registry,
            # which retrieves URLs; only same-document fragments are allowed.
            for key in ("$ref", "$dynamicRef", "$recursiveRef"):
                if key in value and not str(value[key]).startswith("#"):
                    raise ValueError("external schema references are unsupported")
            for child in value.values():
                refs(child)
        elif isinstance(value, list):
            for child in value:
                refs(child)
    refs(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate(schema, sample):
    validator(schema).validate(sample)


def reviewed_schema(schema, expected):
    if expected is not None and hashlib.sha256(json.dumps(schema, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest() != expected:
        raise ValueError("practice questions changed since the exact inspection; no tool action was invoked")


def await_result(value):
    return asyncio.run(value) if inspect.isawaitable(value) else value


def inspect_contract(group, target, name):
    """Describe the declared input only; never invoke a tool action/lifecycle."""
    if group == "maverick.tools":
        tool = target()
        validator(tool.input_schema)
        if not callable(tool.fn):
            raise ValueError("tool has no callable handler")
        return [{"name": name, "input_schema": tool.input_schema}]
    if group == "maverick.personas":
        return [{"name": name, "input_schema": {"type": "object", "additionalProperties": False}}]
    if group == "maverick.skills":
        return [{"name": name, "input_schema": {"type": "object", "properties": {"goal": {"type": "string", "title": "Practice request", "minLength": 1}},
                                                "required": ["goal"], "additionalProperties": False}}]
    if group == "maverick.channels":
        return [{"name": name, "input_schema": {"type": "object", "properties": {
            "user_id": {"type": "string", "title": "Fictional person", "minLength": 1},
            "text": {"type": "string", "title": "Practice message"}, "reply": {"type": "string", "title": "Practice reply"},
            "startup_seconds": {"type": "number", "title": "Seconds to wait for startup", "minimum": 0, "maximum": 5}},
            "required": ["user_id", "text", "reply"], "additionalProperties": False}}]
    raise ValueError("unsupported plugin contract")


def inspect_remote(payload):
    if payload["group"] == "maverick.ts":
        from maverick.ts_plugin_host import _close_all_children, _fetch_manifest, _PinnedCommand
        try:
            _protocol, manifest = _fetch_manifest(_PinnedCommand.from_command(["node", "/candidate/plugin" + payload["source_suffix"]]))
            result = [{"name": item["name"], "input_schema": item["inputSchema"]} for item in manifest]
        finally:
            _close_all_children()
    else:
        from maverick.grpc_plugin_host import _close_all_channels, load_grpc_plugin
        try:
            tools = load_grpc_plugin(payload["target"], command=[payload["runtime"], "/candidate/plugin" + payload["source_suffix"]],
                                     call_timeout=10, strict_schema=True, expected_source_sha256=payload["content_sha256"])
            result = [{"name": item.name, "input_schema": item.input_schema} for item in tools]
        finally:
            _close_all_channels()
    for item in result:
        validator(item["input_schema"])
    return result


def execute(group, target, sample, dispatch, expected_schema=None):
    if group == "maverick.tools":
        tool = target()
        validate(tool.input_schema, sample)
        reviewed_schema(tool.input_schema, expected_schema)
        if not callable(tool.fn):
            raise ValueError("tool has no callable handler")
        dispatch()
        return await_result(tool.fn(sample))
    if group == "maverick.personas":
        schema = inspect_contract(group, target, "")[0]["input_schema"]
        validate(schema, sample)
        reviewed_schema(schema, expected_schema)
        if not callable(target):
            raise ValueError("persona must be a callable renderer")
        dispatch()
        value = target()
        if not isinstance(value, str) or not value.strip():
            raise ValueError("persona must return nonempty prompt text")
        return value
    if group == "maverick.skills":
        from maverick.skills import Skill, _relevant_skills_lexical, render_for_prompt
        schema = inspect_contract(group, target, "")[0]["input_schema"]
        validate(schema, sample)
        reviewed_schema(schema, expected_schema)
        if (not isinstance(target, Skill) or not isinstance(target.name, str) or not target.name
                or not isinstance(target.body, str) or not target.body.strip()
                or not isinstance(target.triggers, list) or not target.triggers
                or any(not isinstance(item, str) or not item for item in target.triggers)
                or not isinstance(target.tools_needed, list)
                or any(not isinstance(item, str) or not item for item in target.tools_needed)):
            raise ValueError("skill has a malformed declared contract")
        dispatch()
        selected = _relevant_skills_lexical(sample["goal"], [target], max_n=1)
        return {"selected": [skill.name for skill in selected], "prompt": render_for_prompt(selected)}
    if group == "maverick.channels":
        from dataclasses import asdict

        from maverick_channels.base import Channel, IncomingMessage, Reply
        schema = inspect_contract(group, target, "")[0]["input_schema"]
        validate(schema, sample)
        reviewed_schema(schema, expected_schema)
        if not isinstance(target, type) or not issubclass(target, Channel):
            raise ValueError("channel must be a concrete Channel subclass")
        async def exercise():
            received = []
            async def handler(message):
                if not isinstance(message, IncomingMessage):
                    raise ValueError("channel dispatched malformed incoming message")
                received.append({"user_id": message.user_id, "text": message.text, "channel": message.channel})
                return Reply(sample["reply"])
            channel = target(handler)
            dispatch()
            started = asyncio.create_task(channel.start())
            try:
                await asyncio.sleep(sample.get("startup_seconds", 0))
                if started.done():
                    started.result()
                reply = await channel.dispatch(IncomingMessage(sample["user_id"], sample["text"], channel=channel.name))
                if not isinstance(reply, Reply):
                    raise ValueError("channel returned an invalid reply")
                await channel.send(sample["user_id"], sample["reply"])
                return {"reply": asdict(reply), "received": received, "send_completed": True}
            finally:
                await channel.stop()
                if not started.done():
                    started.cancel()
                await asyncio.gather(started, return_exceptions=True)
        return asyncio.run(exercise())
    raise ValueError("unsupported plugin contract")


def execute_node(payload, dispatch):
    from maverick.ts_plugin_host import (
        _close_all_children,
        _fetch_manifest,
        _PinnedCommand,
        load_ts_plugin,
    )
    validate({"type": "object", "properties": {"tool": {"type": "string", "minLength": 1},
               "arguments": {"type": "object"}}, "required": ["tool", "arguments"],
               "additionalProperties": False}, payload["sample"])
    command = ["node", "/candidate/plugin" + payload["source_suffix"]]
    pinned = _PinnedCommand.from_command(command)
    protocol, manifest = _fetch_manifest(pinned)
    names = set()
    for entry in manifest:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str) or entry["name"] in names:
            raise ValueError("malformed or duplicate NDJSON tool entry")
        names.add(entry["name"])
        # Validate every declared schema, even when the sample selects another tool.
        schema = entry.get("inputSchema")
        validator(schema)
    chosen = next((item for item in manifest if item["name"] == payload["sample"]["tool"]), None)
    if chosen is None:
        raise ValueError("sample tool is absent from this exact plugin manifest")
    validate(chosen["inputSchema"], payload["sample"]["arguments"])
    try:
        tools = load_ts_plugin(command, call_timeout=20)
        tool = next(item for item in tools if item.name == chosen["name"])
        validate(tool.input_schema, payload["sample"]["arguments"])
        reviewed_schema(tool.input_schema, payload.get("input_schema_sha256"))
        dispatch()
        value = tool.fn(payload["sample"]["arguments"])
        # The actual host preserves transport failure/unknown outcome as ERROR.
        # Matching an expected error string must never qualify a failed call.
        from maverick.tool_results import ToolOutcome, ToolResultText, tool_result_failed

        typed = isinstance(value, (ToolOutcome, ToolResultText))
        if (tool_result_failed(value) if typed else isinstance(value, str) and value.startswith("ERROR:")):
            raise ValueError("NDJSON invocation did not complete with a confirmed result")
        return value
    finally:
        _close_all_children()


def execute_grpc(payload, dispatch):
    from maverick.grpc_plugin_host import _close_all_channels, load_grpc_plugin
    validate({"type": "object", "properties": {"tool": {"type": "string", "minLength": 1},
               "arguments": {"type": "object"}}, "required": ["tool", "arguments"],
               "additionalProperties": False}, payload["sample"])
    try:
        tools = load_grpc_plugin(payload["target"],
            command=[payload["runtime"], "/candidate/plugin" + payload["source_suffix"]],
            call_timeout=20, strict_schema=True, expected_source_sha256=payload["content_sha256"])
        tool = next((item for item in tools if item.name == payload["sample"]["tool"]), None)
        if tool is None:
            raise ValueError("sample tool is absent from the actual gRPC manifest")
        validate(tool.input_schema, payload["sample"]["arguments"])
        reviewed_schema(tool.input_schema, payload.get("input_schema_sha256"))
        dispatch()
        result = tool.fn(payload["sample"]["arguments"])
        if getattr(result, "attempt", None) is None or result.attempt.outcome_unknown or result.startswith("ERROR:"):
            raise ValueError("gRPC invocation did not confirm completion")
        return str(result)
    finally:
        _close_all_channels()
