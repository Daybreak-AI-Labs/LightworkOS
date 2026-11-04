"""Durable delivery decisions and per-node trace behavior."""
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick.flow import node_outcomes
from maverick.flow.continuation_frame import ContinuationFrame
from maverick.flow.execution_trace import ExecutionTrace
from maverick.flow.ir import Flow, FlowNode
from maverick.flow.resume_plan import prepare_resume
from maverick.flow.transitions import (
    DeliveryDecision,
    ResumeDecision,
    decide_delivery,
    decide_resume,
)


@pytest.mark.parametrize("status", ["queued", "claimed"])
def test_fresh_delivery_can_start_only_before_execution(status):
    assert decide_delivery(status) is DeliveryDecision.START


def test_interrupted_running_delivery_is_quarantined():
    assert decide_delivery("running") is DeliveryDecision.QUARANTINE
    for status in (None, "resuming", "completed", "failed", "indeterminate", "paused_approval"):
        assert decide_delivery(status) is DeliveryDecision.RETURN_CHECKPOINT


def test_resume_requires_a_pause_or_an_explicit_retry_with_cursor():
    assert decide_resume("paused_approval", "approve", from_failure=False) is ResumeDecision.APPROVAL
    assert decide_resume("paused_delay", "wait", from_failure=False) is ResumeDecision.PAUSED
    assert decide_resume("failed", "node", from_failure=True) is ResumeDecision.RETRY_FAILURE
    for status, cursor, retry in (("failed", "node", False), ("failed", None, True),
                                  ("completed", "node", True), ("indeterminate", "node", True)):
        assert decide_resume(status, cursor, from_failure=retry) is ResumeDecision.REFUSE


def test_parallel_trace_accumulates_durations_and_records_real_outcomes(monkeypatch):
    recorded = []
    monkeypatch.setattr(node_outcomes, "record", lambda *args, **kwargs: recorded.append((args, kwargs)))
    trace = ExecutionTrace(flow_id="f", revision="r", cohort="c", initial_states={"old": {"status": "done"}},
                           record_outcomes=True, execution_guard=None)
    node = FlowNode(id="shared", kind="action")
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda value: trace.timed(node.id, lambda: value), range(30))) == list(range(30))
    trace.on_node(node, "done", 1.0)
    assert trace.states["old"]["status"] == "done"
    assert trace.states["shared"]["status"] == "done"
    assert trace.states["shared"]["seconds"] >= 0
    assert recorded == [(("f", "shared", "action", 1.0), {"revision": "r", "cohort": "c"})]


def test_failed_guard_does_not_publish_trace_or_outcome(monkeypatch):
    recorded = []
    monkeypatch.setattr(node_outcomes, "record", lambda *args, **kwargs: recorded.append(args))

    def refuse():
        raise RuntimeError("authority changed")

    trace = ExecutionTrace(flow_id="f", revision="r", cohort="c", initial_states={},
                           record_outcomes=True, execution_guard=refuse)
    with pytest.raises(RuntimeError, match="authority changed"):
        trace.on_node(FlowNode(id="node", kind="action"), "done", 1.0)
    assert trace.states == {}
    assert recorded == []


def test_failed_node_checkpoint_retains_cursor_and_nested_invocation():
    raw = {"flow_id": "f", "cursor": "parent", "data": {"value": 1},
           "seen": 4, "children": {"body": {"cursor": "work"}}}
    frame = ContinuationFrame(raw, "f")
    data = {"supplied": "ignored when resuming"}
    assert frame.start(data, "ignored") == ("parent", 4)
    data["output"] = ["saved"]
    frame.checkpoint_data(data)
    data["output"].append("later")
    assert raw["cursor"] == "parent"
    assert raw["children"]["body"]["cursor"] == "work"
    assert raw["data"] == {"value": 1, "output": ["saved"]}
    frame.advance("next", data, 5)
    assert raw == {"flow_id": "f", "cursor": "next", "data": data, "seen": 5}


def test_resume_plan_accepts_only_declared_approval_and_keeps_verdict():
    node = FlowNode(id="approve", kind="approval", next="work", output="answer", choices=["revise"])
    flow = Flow(id="f", name="Example", start="approve", nodes={"approve": node})
    observed = []
    kwargs = dict(data=None, resolve_flow=None, on_node=lambda *args: observed.append(args),
                  approval_outcome=lambda decision: 1.0 if decision == "approved" else None)
    accepted = prepare_resume(flow, resume={"node_id": "approve", "data": {"total": 2},
                                            "decision": "revise"}, **kwargs)
    assert accepted.result is None
    assert accepted.start == "work"
    assert accepted.data == {"total": 2, "answer": "revise"}
    assert observed == [(node, "revise", None)]
    refused = prepare_resume(flow, resume={"node_id": "approve", "decision": "unexpected"}, **kwargs)
    assert refused.result.status == "rejected"


def test_legacy_retry_refuses_an_ambiguous_nested_invocation():
    task = FlowNode(id="work", kind="action")
    nested = Flow(id="child", name="Child", start="work", nodes={"work": task})
    scope = FlowNode(id="scope", kind="scope", body=nested)
    flow = Flow(id="f", name="Example", start="work", nodes={"work": task, "scope": scope})
    plan = prepare_resume(flow, data=None, resume={"node_id": "work", "rerun": True},
                          resolve_flow=None, on_node=None, approval_outcome=lambda _decision: None)
    assert plan.result.status == "indeterminate"
    assert plan.result.cursor == "work"
