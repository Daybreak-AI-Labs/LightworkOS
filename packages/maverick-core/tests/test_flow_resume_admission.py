"""Durable resume admission cannot replay unknown or unreviewed work."""
import pytest
from maverick.flow import store
from maverick.flow.execution import FlowNotResumable, _approval_actor_matches
from maverick.flow.ir import Flow, FlowNode
from maverick.flow.resume_admission import prepare_saved_resume


def _prepare(flow, **overrides):
    params = {
        "run_id": "run", "owner": "", "inputs": None, "from_failure": False,
        "budget_limit_dollars": None, "decision": None, "decided_by": "",
        "expired": False, "approval_binding": "", "expiry_binding": "",
        "actor_matches": _approval_actor_matches, "not_resumable": FlowNotResumable,
    }
    params.update(overrides)
    return prepare_saved_resume(flow, **params)


@pytest.mark.parametrize("status,cursor,retry", [
    ("completed", "node", True), ("indeterminate", "node", True),
    ("failed", "node", False), ("failed", None, True),
])
def test_resume_refuses_terminal_or_ambiguous_checkpoints(monkeypatch, status, cursor, retry):
    prior = store.FlowRun(run_id="run", flow_id="f", status=status, cursor=cursor)
    monkeypatch.setattr(store, "load_run", lambda _run_id: prior)
    with pytest.raises(FlowNotResumable):
        _prepare(Flow(id="f", name="Example", start="node"), from_failure=retry)
    assert prior.status == status


def test_resume_uses_saved_graph_and_cannot_replace_reviewed_values(monkeypatch):
    paused = FlowNode(id="review", kind="approval", form=[{"name": "note"}], assignee="alice")
    saved = Flow(id="f", name="Saved", start="review", nodes={"review": paused})
    prior = store.FlowRun(
        run_id="run", flow_id="f", status="paused_approval", cursor="review",
        owner="user:alice", data={"amount": 10}, definition_digest="saved-digest",
    )
    monkeypatch.setattr(store, "load_run", lambda _run_id: prior)
    monkeypatch.setattr(store, "load_flow_snapshot", lambda _digest: saved)
    supplied = Flow(id="f", name="Edited", start="review")
    admission = _prepare(supplied, inputs={"amount": 999, "note": "approved", "extra": "x"},
                         decision="approved", decided_by="user:alice", approval_binding="binding")
    assert admission.flow is saved
    assert admission.owner == "user:alice"
    assert admission.resume == {"node_id": "review", "data": {"amount": 10, "note": "approved"},
                                "decision": "approved"}
    assert admission.submitted_inputs == {"amount": 999, "note": "approved", "extra": "x"}
    assert admission.approval_binding == "binding"
    assert prior.status == "paused_approval"


def test_retry_from_budget_hold_requires_a_larger_finite_total(monkeypatch):
    prior = store.FlowRun(run_id="run", flow_id="f", status="budget_limited", cursor="node",
                          cost_dollars=4.0, budget_limit_dollars=5.0)
    monkeypatch.setattr(store, "load_run", lambda _run_id: prior)
    flow = Flow(id="f", name="Example", start="node")
    for invalid in (5.0, float("nan"), True):
        with pytest.raises(FlowNotResumable):
            _prepare(flow, from_failure=True, budget_limit_dollars=invalid)
    admission = _prepare(flow, from_failure=True, budget_limit_dollars=6.0)
    assert admission.resume["rerun"] is True


def test_retry_from_failure_cannot_reuse_an_approval_for_a_high_risk_action(monkeypatch):
    gate = FlowNode(id="gate", kind="approval", assignee="cfo", next="pay")
    pay = FlowNode(id="pay", kind="action", tool="slack_bot", params={"text": "x"})
    flow = Flow(id="f", name="Example", start="gate", nodes={"gate": gate, "pay": pay})
    prior = store.FlowRun(run_id="run", flow_id="f", status="failed", cursor="pay",
                          continuation={"node_id": "pay"})
    monkeypatch.setattr(store, "load_run", lambda _run_id: prior)
    with pytest.raises(FlowNotResumable, match="without a new review"):
        _prepare(flow, from_failure=True)
    assert prior.status == "failed"


def test_budget_hold_resumes_unless_a_branch_stopped_at_its_gated_action(monkeypatch):
    body = Flow(id="body", name="b", start="work", nodes={
        "work": FlowNode(id="work", kind="agent", brief="x", next="pay"),
        "pay": FlowNode(id="pay", kind="action", tool="slack_bot", params={"text": "x"})})
    flow = Flow(id="f", name="Example", start="gate", nodes={
        "gate": FlowNode(id="gate", kind="approval", next="loop"),
        "loop": FlowNode(id="loop", kind="foreach", items="xs", body=body, concurrent=True)})
    held = {"flow_id": "body", "cursor": "work", "data": {}, "seen": 0}
    done = {"flow_id": "body", "cursor": None, "data": {}, "seen": 2}
    frame = {"flow_id": "f", "cursor": "loop", "data": {}, "seen": 0,
             "children": {"0": done, "1": held}}
    prior = store.FlowRun(run_id="run", flow_id="f", status="budget_limited", cursor="loop",
                          cost_dollars=4.0, budget_limit_dollars=5.0,
                          continuation={"version": 1, "frame": frame})
    monkeypatch.setattr(store, "load_run", lambda _run_id: prior)
    assert _prepare(flow, from_failure=True, budget_limit_dollars=6.0).resume["rerun"] is True
    frame["children"]["2"] = {"flow_id": "body", "cursor": "pay", "data": {}, "seen": 1}
    with pytest.raises(FlowNotResumable, match="without a new review"):
        _prepare(flow, from_failure=True, budget_limit_dollars=6.0)
