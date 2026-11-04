"""Durable nested retries retain invocation identity and completed work."""
from __future__ import annotations

from collections import Counter

import pytest
from maverick.budget import BudgetExceeded
from maverick.flow import Flow, FlowNode, execution, store
from maverick.flow.runner import run_flow
from maverick.killswitch import Halted


def graph(name, *nodes):
    return Flow(id=name, name=name, start=nodes[0].id, nodes={n.id: n for n in nodes})


def action(name, phase, **kwargs):
    return FlowNode(id=name, kind="action", tool="web_search",
                    params={"phase": phase, "item": "{{item}}"}, **kwargs)


@pytest.mark.parametrize("concurrent", [False, True])
def test_durable_foreach_retry_preserves_exact_iteration_and_completed_effects(concurrent):
    body = graph("body", action("before", "before", next="finish"),
                 action("finish", "finish", output="answer"))
    flow = graph("batch", FlowNode(id="loop", kind="foreach", items="items", var="item",
                                  body=body, concurrent=concurrent, output="orders", next="finish"),
                 action("finish", "outer"))
    calls = Counter()
    failed = False

    def execute_action(tool, params, data):
        nonlocal failed
        key = (params["phase"], params["item"])
        if key == ("finish", "b") and not failed:
            failed = True
            raise RuntimeError("definitive retry-safe failure")
        calls[key] += 1
        return "delivered:" + params["item"], 1.0

    first = execution.execute(flow, agent_runner=lambda *_: ("", 1.0),
                              action_runner=execute_action, data={"items": ["a", "b", "c"]})
    assert first.status == "failed"
    loaded = store.load_run(first.run_id)
    assert loaded.cursor == "loop" and loaded.continuation["version"] == 1
    assert "continuation" not in loaded.to_dict()
    second = execution.execute(flow, agent_runner=lambda *_: ("", 1.0),
                               action_runner=execute_action, resume_run_id=first.run_id,
                               from_failure=True)
    assert second.status == "completed"
    assert [row["answer"] for row in second.data["orders"]] == [
        "delivered:a", "delivered:b", "delivered:c",
    ]
    assert all(value == 1 for value in calls.values())
    assert len(calls) == 7


@pytest.mark.parametrize("container", ["scope", "parallel", "subflow", "scoped_subflow"])
def test_nested_container_retry_skips_completed_prefix(container):
    body = graph("body", action("before", "before", next="finish"),
                 action("finish", "finish", output="answer"))
    if "subflow" in container:
        store.save_flow(body)
        wrapper = FlowNode(id="nested", kind="subflow", flow_ref=body.id,
                           subflow_inputs={"item": "{{item}}"} if container == "scoped_subflow" else {},
                           output="result", next="finish")
    elif container == "parallel":
        sibling = graph("sibling", action("finish", "sibling"))
        wrapper = FlowNode(id="nested", kind="parallel", branches=[body, sibling], next="finish")
    else:
        wrapper = FlowNode(id="nested", kind="scope", body=body, next="finish")
    flow = graph("top", wrapper, action("finish", "outer"))
    calls = Counter()
    failed = False

    def run(tool, params, data):
        nonlocal failed
        if params["phase"] == "finish" and not failed:
            failed = True
            raise RuntimeError("try later")
        calls[params["phase"]] += 1
        return "ok", 1.0

    first = execution.execute(flow, agent_runner=lambda *_: ("", 1), action_runner=run,
                              data={"item": "a"})
    assert first.status == "failed"
    second = execution.execute(flow, agent_runner=lambda *_: ("", 1), action_runner=run,
                               resume_run_id=first.run_id, from_failure=True)
    assert second.status == "completed"
    assert all(value == 1 for value in calls.values())
    assert calls["before"] == calls["finish"] == calls["outer"] == 1


@pytest.mark.parametrize("signal", [Halted, BudgetExceeded])
@pytest.mark.parametrize("container", ["scope", "foreach", "parallel", "subflow"])
def test_control_stop_cannot_be_caught_as_a_business_error(signal, container):
    body = graph("body", action("fail", "fail"))
    kwargs = {"body": body}
    if container == "foreach":
        kwargs.update(items="items", var="item")
    elif container == "parallel":
        kwargs = {"branches": [body]}
    elif container == "subflow":
        kwargs = {"flow_ref": "body"}
    flow = graph("flow", FlowNode(id="nested", kind=container, on_error="fallback", **kwargs),
                 FlowNode(id="fallback", kind="setvar", assignments={"incorrect": True}))

    def stopped(*_):
        raise signal("operator stop", "test") if signal is Halted else signal("operator stop")

    with pytest.raises(signal):
        run_flow(flow, agent_fn=stopped, action_fn=stopped, data={"items": [1]},
                 resolve_flow=lambda _: body)


def test_budget_refusal_is_durable_non_success_without_downstream_or_learning(monkeypatch):
    flow = graph("budget", FlowNode(id="first", kind="agent", brief="first", next="price"),
                 FlowNode(id="price", kind="agent", brief="price", output="quote", next="send"),
                 action("send", "send"))
    flow.max_dollars = 5
    effects, signals = [], []
    monkeypatch.setattr(execution.node_outcomes, "record", lambda *a, **k: signals.append(a))
    run = execution.execute(flow, agent_runner=lambda *_: ("ok", 1.0),
                            action_runner=lambda *a: effects.append(a), origin="event:test")
    assert run.status == "budget_limited"
    assert "quote" not in run.data and effects == []
    assert run.cursor == "price" and run.continuation
    assert store.load_run(run.run_id).status == "budget_limited"
    assert [row[1] for row in signals] == ["first"]
    resumed = execution.execute(
        flow, agent_runner=lambda *_: ("actual quote", 1.0),
        action_runner=lambda *a: (effects.append(a) or "sent", 1.0),
        resume_run_id=run.run_id, from_failure=True, budget_limit_dollars=10,
    )
    assert resumed.status == "completed" and resumed.data["quote"] == "actual quote"
    assert resumed.cost_dollars == 10 and len(effects) == 1
    assert [row[1] for row in signals].count("first") == 1


def test_legacy_nested_leaf_cursor_is_not_reinterpreted_as_outer_node():
    body = graph("body", action("finish", "inner"))
    flow = graph("flow", FlowNode(id="loop", kind="foreach", items="items", body=body),
                 action("finish", "outer"))
    calls = []
    result = run_flow(flow, agent_fn=lambda *_: ("", 1), action_fn=lambda *a: calls.append(a),
                      resume={"node_id": "finish", "data": {"items": [1]}, "rerun": True})
    assert result.status == "indeterminate" and calls == []
    assert "invocation history" in result.error


def test_production_flow_uses_actual_usage_without_a_generated_task_cap(monkeypatch):
    from types import SimpleNamespace

    from maverick import runner

    calls = []
    origins = []

    class World:
        def create_goal(self, *_args, **_kw):
            return len(calls) + 1

        def get_goal(self, _gid):
            return SimpleNamespace(status="done", result="customer result")

        def record_goal_origin(self, gid, source, correlation):
            origins.append((gid, source, correlation))

    def dispatch(_gid, **kwargs):
        calls.append(kwargs)
        kwargs["usage_observer"](0.123456)
        return "done"

    monkeypatch.setattr(runner, "run_goal_in_thread", dispatch)
    monkeypatch.setattr(runner, "configured_max_dollars", lambda: None)
    monkeypatch.setattr(runner, "configured_max_wall_seconds", lambda: None)
    monkeypatch.setattr(execution, "_capture_node_tools", lambda *_a, **_k: None)
    flow = graph("metered", FlowNode(id="a", kind="agent", brief="a", next="b"),
                 FlowNode(id="b", kind="agent", brief="b", output="answer"))
    run = execution.execute(flow, agent_runner=execution.default_agent_runner(World()),
                            action_runner=lambda *_: ("", 1.0))
    assert run.status == "completed" and run.data["answer"] == "customer result"
    assert run.cost_dollars == pytest.approx(0.246912)
    assert origins == [(1, "flow_run", run.run_id), (2, "flow_run", run.run_id)]
    assert all(c["max_dollars"] is None and c["max_wall_seconds"] is None for c in calls)


def test_metered_flow_admits_remaining_real_allowance(monkeypatch):
    allowances = []

    def metered(_brief, _data, *, allowance):
        allowances.append(allowance)
        return execution._MeteredAgentResult("ok", 1.0, 0.25)

    metered._meters_usage = True
    flow = graph("metered-cap", FlowNode(id="a", kind="agent", brief="a", next="b"),
                 FlowNode(id="b", kind="agent", brief="b", next="c"),
                 FlowNode(id="c", kind="agent", brief="c"))
    flow.max_dollars = 0.5
    result = execution.execute(flow, agent_runner=metered, action_runner=lambda *_: ("", 1))
    assert allowances == [0.5, 0.25]
    assert result.status == "budget_limited" and result.cursor == "c"
    assert result.cost_dollars == 0.5


def test_production_action_halt_escapes_scope_without_fallback(monkeypatch):
    from types import SimpleNamespace

    from maverick import audit, tool_authz, tools

    class Registry:
        def all(self):
            return [SimpleNamespace(name="web_search")]

        async def run(self, *_):
            raise Halted("operator stopped this run", "file")

    monkeypatch.setattr(tool_authz, "authorize", lambda *_a, **_kw: None)
    monkeypatch.setattr(tools, "base_registry", lambda *_a, **_kw: Registry())
    monkeypatch.setattr(audit, "audit_event", lambda *_a, **_kw: True)
    body = graph("body", action("call", "call"))
    flow = graph("production-stop", FlowNode(id="scope", kind="scope", body=body, on_error="fallback"),
                 FlowNode(id="fallback", kind="setvar", assignments={"wrong": True}))
    statuses = []
    run_action = execution.default_action_runner(None, sandbox=object())
    with pytest.raises(Halted):
        run_flow(flow, agent_fn=lambda *_: ("", 1),
                 action_fn=lambda _n, params, data: run_action("web_search", params, data),
                 on_node=lambda n, *_: statuses.append(n.id))
    assert "fallback" not in statuses


def test_shared_subflow_retry_preserves_outputs_created_before_failure():
    body = graph("child-output", action("before", "before", output="kept", next="finish"),
                 action("finish", "finish", output="last"))
    flow = graph("parent-output", FlowNode(id="child", kind="subflow", flow_ref=body.id, output="answer"))
    store.save_flow(body)
    attempts = Counter()

    def execute_action(_tool, params, _data):
        phase = params["phase"]
        attempts[phase] += 1
        if phase == "finish" and attempts[phase] == 1:
            raise RuntimeError("temporary read failure")
        return phase, 1.0

    first = execution.execute(flow, agent_runner=lambda *_: ("", 1), action_runner=execute_action)
    second = execution.execute(flow, agent_runner=lambda *_: ("", 1), action_runner=execute_action,
                               resume_run_id=first.run_id, from_failure=True)
    assert second.status == "completed"
    assert second.data["answer"] == {"kept": "before", "last": "finish"}
    assert attempts == {"before": 1, "finish": 2}


def test_while_retry_finishes_current_iteration_before_rechecking_condition():
    body = graph("while-body", action("before", "before", next="finish"),
                 action("finish", "finish"))
    flow = graph("while-parent", FlowNode(id="loop", kind="while", condition="done != yes",
                                         body=body, output="passes"))
    attempts = Counter()

    def execute_action(_tool, params, data):
        phase = params["phase"]
        attempts[phase] += 1
        if phase == "before":
            data["done"] = "yes"
        if phase == "finish" and attempts[phase] == 1:
            raise RuntimeError("read failed")
        return "ok", 1.0

    first = execution.execute(flow, agent_runner=lambda *_: ("", 1), action_runner=execute_action,
                              data={"done": "no"})
    second = execution.execute(flow, agent_runner=lambda *_: ("", 1), action_runner=execute_action,
                               resume_run_id=first.run_id, from_failure=True)
    assert second.status == "completed" and second.data["passes"] == 1
    assert attempts == {"before": 1, "finish": 2}
