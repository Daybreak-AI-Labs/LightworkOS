"""slack_workflow: workflow custom-step JSON builder. No network."""
from __future__ import annotations

import json

from maverick.tools.slack_workflow import slack_workflow


def _run(**kw):
    return slack_workflow().fn(kw)


def test_build_step_definition():
    out = _run(
        op="build_step",
        name="Summarize Thread",
        inputs={"channel": {"type": "slack#/types/channel_id"}, "text": {"type": "string"}},
        outputs=[{"name": "summary", "type": "string"}],
    )
    obj = json.loads(out)
    assert obj["title"] == "Summarize Thread"
    assert obj["callback_id"] == "summarize_thread"  # derived from name
    assert obj["input_parameters"]["properties"]["text"] == {"type": "string"}
    assert obj["input_parameters"]["required"] == ["channel", "text"]
    assert obj["output_parameters"]["properties"]["summary"] == {"type": "string"}


def test_build_step_derived_callback_id_from_digit_leading_name():
    # Regression: a name starting with a digit derived a callback_id like
    # "2027_report" that violates Slack's ^[a-z][a-z0-9_]* rule (the same rule
    # rejected if supplied explicitly). The derived id must be prefixed to stay
    # valid.
    out = _run(
        op="build_step",
        name="2027 report",
        inputs={"x": {"type": "string"}},
    )
    obj = json.loads(out)
    cb = obj["callback_id"]
    assert cb[0].isalpha(), cb
    assert cb == "s_2027_report"


def test_build_step_explicit_callback_id():
    out = _run(
        op="build_step",
        name="Step",
        callback_id="my_step",
        inputs={"x": {"type": "string"}},
    )
    obj = json.loads(out)
    assert obj["callback_id"] == "my_step"
    assert obj["output_parameters"]["properties"] == {}  # outputs optional


def test_trigger_payload():
    out = _run(op="trigger_payload", callback_id="my_step", values={"x": "hi", "n": 3})
    obj = json.loads(out)
    assert obj["type"] == "workflow_step_execute"
    assert obj["callback_id"] == "my_step"
    assert obj["inputs"] == {"x": {"value": "hi"}, "n": {"value": 3}}


def test_build_step_validation():
    assert _run(op="build_step", name="S").startswith("ERROR")  # no inputs
    bad_key = _run(op="build_step", name="S", inputs={"Bad Key": {"type": "string"}})
    assert bad_key.startswith("ERROR")
    no_type = _run(op="build_step", name="S", inputs={"x": {}})
    assert no_type.startswith("ERROR") and "missing type" in no_type


def test_trigger_payload_validation():
    assert _run(op="trigger_payload", values={"x": 1}).startswith("ERROR")  # no callback_id
    assert _run(op="trigger_payload", callback_id="s").startswith("ERROR")  # no values


def test_errors():
    t = slack_workflow()
    assert t.fn({"op": "build_step"}).startswith("ERROR")  # no name
    assert t.fn({"op": "nope"}).startswith("ERROR")
