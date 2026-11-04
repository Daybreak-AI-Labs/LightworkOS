"""Resource caps: a whole-flow wall-clock deadline and a per-node soft timeout."""
from __future__ import annotations

import time

from maverick.flow import Flow, FlowNode
from maverick.flow.runner import run_flow


def test_flow_deadline_fails_the_run():
    # a clock that jumps past the deadline before the second node runs
    ticks = iter([0.0, 0.0, 100.0, 100.0, 100.0])
    now = lambda: next(ticks, 100.0)          # noqa: E731
    f = Flow(id="f", name="f", start="a", max_seconds=10.0, nodes={
        "a": FlowNode(id="a", kind="agent", brief="one", next="b"),
        "b": FlowNode(id="b", kind="agent", brief="two")})
    res = run_flow(f, agent_fn=lambda n, br, d: ("x", 1.0),
                   action_fn=lambda *a: ("", None), now=now)
    assert res.status == "failed" and "deadline" in res.error


def test_no_deadline_when_unset():
    f = Flow(id="f", name="f", start="a", nodes={
        "a": FlowNode(id="a", kind="agent", brief="one")})
    res = run_flow(f, agent_fn=lambda n, br, d: ("x", 1.0), action_fn=lambda *a: ("", None))
    assert res.status == "completed"


def test_node_timeout_preserves_eventual_success_before_downstream_work():
    def slow_action(node, params, data):
        time.sleep(0.3)
        return ("done", 1.0)
    f = Flow(id="f", name="f", start="a", nodes={
        "a": FlowNode(id="a", kind="action", tool="t", timeout=0.05, output="r", next="b"),
        "b": FlowNode(id="b", kind="agent", brief="after", output="done")})
    res = run_flow(f, agent_fn=lambda n, br, d: ("ok", 1.0), action_fn=slow_action)
    assert res.status == "completed"
    assert res.data["r"] == "done"
    assert res.data["done"] == "ok"


def test_fast_node_under_timeout_succeeds():
    f = Flow(id="f", name="f", start="a", nodes={
        "a": FlowNode(id="a", kind="action", tool="t", timeout=2.0, output="r")})
    res = run_flow(f, agent_fn=lambda *a: ("", None),
                   action_fn=lambda n, p, d: ("quick", 1.0))
    assert res.status == "completed" and res.data["r"] == "quick"


def test_timed_out_success_is_not_retried_or_abandoned():
    active = 0
    max_active = 0
    calls = 0

    def slow_action(node, params, data):
        nonlocal active, max_active, calls
        calls += 1
        active += 1
        max_active = max(max_active, active)
        try:
            time.sleep(0.08)
            return ("done", 1.0)
        finally:
            active -= 1

    f = Flow(id="f", name="f", start="a", nodes={
        "a": FlowNode(id="a", kind="action", tool="t", timeout=0.01, retries=3, output="r")})
    res = run_flow(f, agent_fn=lambda *a: ("", None), action_fn=slow_action)

    assert res.status == "completed"
    assert res.data["r"] == "done"
    assert calls == 1
    assert max_active == 1
    assert active == 0
