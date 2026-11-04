"""autogen_adapter: Microsoft AutoGen tool-spec translation."""
from __future__ import annotations

import json

from maverick.tools.autogen_adapter import autogen_adapter


def _run(**kw):
    return autogen_adapter().fn(kw)


def test_tool_spec_shape():
    out = _run(
        op="tool_spec",
        name="read_file",
        description="Read a file from the workspace.",
        params_schema={"type": "object", "properties": {"path": {"type": "string"}}},
    )
    spec = json.loads(out)
    assert spec["type"] == "function"
    assert spec["function"]["name"] == "read_file"
    assert spec["function"]["description"] == "Read a file from the workspace."
    assert spec["function"]["parameters"]["properties"]["path"]["type"] == "string"


def test_tool_spec_defaults_empty_schema_and_type():
    # No params_schema -> a valid empty object schema; bare properties -> type added.
    out = json.loads(_run(op="tool_spec", name="ping", description="ping"))
    assert out["function"]["parameters"] == {"type": "object", "properties": {}}
    out2 = json.loads(
        _run(op="tool_spec", name="x", description="x", params_schema={"properties": {}})
    )
    assert out2["function"]["parameters"]["type"] == "object"


def test_from_autogen_wrapped_form():
    spec = {
        "type": "function",
        "function": {
            "name": "search",
            "description": "Search the web.",
            "parameters": {"type": "object", "properties": {"q": {"type": "string"}}},
        },
    }
    out = json.loads(_run(op="from_autogen", spec=spec))
    assert out == {
        "name": "search",
        "description": "Search the web.",
        "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}},
    }


def test_from_autogen_bare_function_and_round_trip():
    bare = {"name": "noop", "parameters": {"type": "object", "properties": {}}}
    out = json.loads(_run(op="from_autogen", spec=bare))
    assert out["name"] == "noop"
    assert out["description"] == ""  # missing description -> empty string
    # tool_spec -> from_autogen preserves name/description/schema.
    spec = _run(op="tool_spec", name="t", description="d",
                params_schema={"type": "object", "properties": {"a": {"type": "integer"}}})
    back = json.loads(_run(op="from_autogen", spec=json.loads(spec)))
    assert back["name"] == "t" and back["description"] == "d"
    assert back["input_schema"]["properties"]["a"]["type"] == "integer"


def test_errors():
    t = autogen_adapter()
    assert t.fn({"op": "tool_spec", "description": "d"}).startswith("ERROR")  # no name
    assert t.fn({"op": "tool_spec", "name": "n"}).startswith("ERROR")  # no description
    assert t.fn({"op": "from_autogen", "spec": {}}).startswith("ERROR")  # empty spec
    assert t.fn({"op": "from_autogen", "spec": {"description": "x"}}).startswith("ERROR")
    assert t.fn({"op": "nope"}).startswith("ERROR")


def test_factory_contract():
    t = autogen_adapter()
    assert t.name == "autogen_adapter"
    assert t.parallel_safe is True
    assert t.input_schema["type"] == "object"
    assert set(t.input_schema["properties"]["op"]["enum"]) == {"tool_spec", "from_autogen"}
