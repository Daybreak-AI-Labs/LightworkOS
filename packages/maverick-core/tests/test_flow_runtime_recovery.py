"""Refusals and retries preserve the interpreter's effect boundaries."""
from __future__ import annotations

import copy

import pytest
from maverick.flow import Flow, FlowNode, execution
from maverick.flow.runner import run_flow


def graph(name, *nodes):
    return Flow(id=name, name=name, start=nodes[0].id, nodes={n.id: n for n in nodes})


def run(flow, **kwargs):
    return run_flow(flow, agent_fn=lambda *_: pytest.fail("unexpected agent"),
                    action_fn=kwargs.pop("action_fn", lambda *_: ("ok", 1.0)), **kwargs)


def test_foreach_refuses_non_lists_before_running_any_body():
    body = graph("body", FlowNode(id="read", kind="action", tool="web_search"))
    flow = graph("foreach", FlowNode(id="loop", kind="foreach", items="rows", body=body))
    effects = []
    for value in ("abc", {"a": 1}, None, 3, (1, 2)):
        result = run(flow, data={"rows": value},
                     action_fn=lambda *_: (effects.append(True), 1.0))
        assert result.status == "failed" and "list" in result.error.lower()
        assert result.cursor == "loop" and effects == []
    assert run(flow, data={"rows": []}).status == "completed"
    assert run(flow, data={"rows": [1, 2]},
               action_fn=lambda *_: (effects.append(True), 1.0)).status == "completed"
    assert len(effects) == 2


def test_action_parameters_render_nested_strings_once():
    params = {"top": "{{value}}", "nested": {"text": "{{value}}"},
              "rows": ["{{value}}", {"number": 4, "enabled": True}]}
    before = copy.deepcopy(params)
    flow = graph("params", FlowNode(id="send", kind="action", tool="web_search", params=params))
    calls = []
    result = run(flow, data={"value": "{{other}}", "other": "must not render again"},
                 action_fn=lambda _n, values, _d: (calls.append(values), 1.0))
    assert result.status == "completed"
    assert calls == [{"top": "{{other}}", "nested": {"text": "{{other}}"},
                      "rows": ["{{other}}", {"number": 4, "enabled": True}]}]
    assert params == before


@pytest.mark.parametrize("handler", ["none", "node", "scope"])
def test_data_credential_refusal_is_a_catchable_step_failure(handler):
    action = FlowNode(id="send", kind="action", tool="wire_transfer",
                      params={"message": "{{message}}", "nested": {"text": "{{nested_message}}"}}, retries=3,
                      on_error="recover" if handler == "node" else None)
    recovery = FlowNode(id="recover", kind="setvar", assignments={"recovered": True})
    body = graph("body", action, recovery)
    flow = (graph("outer", FlowNode(id="scope", kind="scope", body=body, on_error="recover"), recovery)
            if handler == "scope" else body)
    effects = []
    for data in ({"message": "hello {{secret('fixture')}}", "nested_message": "ordinary text"},
                 {"message": "ordinary text", "nested_message": "{{upper(secret('fixture'))}}"}):
        result = run(flow, data=data,
                     action_fn=lambda *_: (effects.append(True), 1.0))
        assert effects == []
        if handler == "none":
            assert result.status == "failed" and result.cursor == "send"
            assert result.continuation and "Connections" in result.error
        else:
            assert result.status == "completed" and result.data["recovered"] is True
    legitimate = run(flow, data={"message": "ordinary business text", "nested_message": "more text"},
                     action_fn=lambda *_: (effects.append(True), 1.0))
    assert legitimate.status == "completed" and effects == [True]


def test_switch_missing_and_null_values_take_default():
    flow = graph("switch", FlowNode(id="route", kind="switch", condition="value",
                                   cases=[{"value": "None", "to": "matched"}], next="default"),
                 FlowNode(id="matched", kind="setvar", assignments={"route": "matched"}),
                 FlowNode(id="default", kind="setvar", assignments={"route": "default"}))
    for data in ({}, {"value": None}):
        assert run(flow, data=data).data["route"] == "default"
    assert run(flow, data={"value": "None"}).data["route"] == "matched"


def test_rejected_choice_rejects_both_inline_and_resumed_approvals():
    flow = graph("choice", FlowNode(id="review", kind="approval", prompt="Choose a verdict", choices=["rejected", "hold"],
                                   output="choice", next="after"),
                 FlowNode(id="after", kind="setvar", assignments={"continued": True}))
    assert flow.validate() == []
    inline = run(flow, approve_fn=lambda *_: "rejected")
    paused = run(flow)
    resumed = run(flow, resume={"node_id": paused.cursor, "data": paused.data, "decision": "rejected"})
    for result in (inline, resumed):
        assert result.status == "rejected" and "continued" not in result.data
    assert run(flow, approve_fn=lambda *_: "hold").data["choice"] == "hold"


@pytest.mark.parametrize("nested", [False, True])
def test_pre_dispatch_refusal_retries_its_exact_container(nested):
    body = graph("body", FlowNode(id="read", kind="action", tool="web_search"))
    loop = graph("batch", FlowNode(id="loop", kind="foreach", items="rows", body=body))
    flow = graph("outer", FlowNode(id="scope", kind="scope", body=loop)) if nested else loop
    runners = {"agent_runner": lambda *_: pytest.fail("unexpected agent"),
               "action_runner": lambda *_: pytest.fail("unexpected action")}
    result = execution.execute(flow, data={"rows": list(range(1001))}, **runners)
    assert result.status == "failed" and "1,001 items" in result.error
    assert result.cursor == ("scope" if nested else "loop")
    assert result.continuation
    resumed = execution.execute(flow, resume_run_id=result.run_id, from_failure=True, **runners)
    assert resumed.status == "failed" and resumed.error == result.error
    assert resumed.continuation and resumed.cursor == result.cursor


def test_post_effect_observer_failure_cannot_make_action_retryable():
    flow = graph("effect", FlowNode(id="send", kind="action", tool="wire_transfer", output="receipt", next="after"),
                 FlowNode(id="after", kind="setvar", assignments={"continued": True}))
    effects = []

    def observer(_node, status, _outcome):
        assert status == "done"
        raise RuntimeError("observer failed after delivery")

    result = run(flow, action_fn=lambda *_: (effects.append("sent"), 1.0), on_node=observer)
    assert effects == ["sent"]
    assert result.status == "indeterminate" and result.cursor == "send"
    assert not result.continuation
    assert "receipt" not in result.data and "continued" not in result.data


def test_nested_retry_refuses_new_inputs_instead_of_silently_discarding_them():
    body = graph("body", FlowNode(id="read", kind="action", tool="web_search"))
    flow = graph("outer", FlowNode(id="scope", kind="scope", body=body))
    calls = []

    def unavailable(*_):
        calls.append("failed")
        raise RuntimeError("temporary read failure")

    failed = execution.execute(flow, data={"saved": "value"}, action_runner=unavailable,
                               agent_runner=lambda *_: pytest.fail("unexpected agent"))
    assert failed.status == "failed" and failed.continuation
    runners = {"agent_runner": lambda *_: pytest.fail("unexpected agent"),
               "action_runner": lambda *_: (calls.append("retried"), 1.0)}
    refused = execution.execute(flow, resume_run_id=failed.run_id, from_failure=True,
                                inputs={"operator_note": "new"}, **runners)
    assert refused.status == "failed" and "new inputs" in refused.error.lower()
    assert calls == ["failed"] and refused.continuation == failed.continuation
    resumed = execution.execute(flow, resume_run_id=failed.run_id, from_failure=True, **runners)
    assert resumed.status == "completed" and calls == ["failed", "retried"]
