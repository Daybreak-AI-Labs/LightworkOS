"""Approved effects retain their validation and durable-claim ordering."""
from contextlib import nullcontext

import pytest
from maverick.approval_cards import ApprovalCardError
from maverick.flow import approvals, store
from maverick.flow.approval_dispatch import ApprovalDispatch
from maverick.flow.approval_resume import prepare_approval_decision
from maverick.flow.execution import _approval_actor_matches
from maverick.flow.ir import Flow, FlowNode
from maverick.flow.runner import FlowApprovalStale


def _dispatch(prior, action):
    return ApprovalDispatch(
        action_runner=action,
        flow=Flow(id="f", name="Example", start="action"),
        prior=prior,
        snapshot=store.FlowRun(run_id="run", flow_id="f", status="paused_approval"),
        approval_resume=True,
        submitted_inputs={"answer": "yes"},
        binding="binding",
        authority_binding="authority",
        decision="approved",
        actor="user:approver",
        expired=False,
        decision_attestation=None,
    )


def test_approval_is_rechecked_each_effect_but_resume_is_claimed_once(monkeypatch):
    events = []
    prior = store.FlowRun(run_id="run", flow_id="f", status="paused_approval")
    monkeypatch.setattr("maverick.authority_effects.authority_effect_fence", nullcontext)
    monkeypatch.setattr(approvals, "require_current_paused_operation",
                        lambda *args, **kwargs: events.append("validated"))
    monkeypatch.setattr(store, "save_run", lambda run: events.append((run.status, run.decided_by)))

    def perform(tool, params, data):
        events.append(("effect", tool))
        return "done"

    dispatcher = _dispatch(prior, perform)
    node = FlowNode(id="action", kind="action", tool="send")
    assert dispatcher(node, {}, {}) == "done"
    assert dispatcher(node, {}, {}) == "done"
    assert events == ["validated", ("resuming", "user:approver"), ("effect", "send"),
                      "validated", ("effect", "send")]


def test_stale_approval_before_first_effect_keeps_the_saved_pause(monkeypatch):
    prior = store.FlowRun(run_id="run", flow_id="f", status="paused_approval")
    effects = []
    monkeypatch.setattr("maverick.authority_effects.authority_effect_fence", nullcontext)

    def reject(*args, **kwargs):
        raise ApprovalCardError("authority changed")

    monkeypatch.setattr(approvals, "require_current_paused_operation", reject)
    monkeypatch.setattr(store, "save_run", lambda run: effects.append("saved"))
    dispatcher = _dispatch(prior, lambda *args: effects.append("effect"))
    with pytest.raises(FlowApprovalStale):
        dispatcher(FlowNode(id="action", kind="action", tool="send"), {}, {})
    assert prior.status == "paused_approval"
    assert effects == []


def test_approval_resume_without_reviewed_snapshot_cannot_invoke_effect():
    prior = store.FlowRun(run_id="run", flow_id="f", status="paused_approval")
    effects = []
    dispatcher = _dispatch(prior, lambda *args: effects.append("effect"))
    dispatcher.snapshot = None
    with pytest.raises(RuntimeError, match="reviewed snapshot"):
        dispatcher(FlowNode(id="action", kind="action", tool="send"), {}, {})
    assert effects == []


def test_approval_decision_binds_the_saved_assignee_and_submitted_choice():
    paused = FlowNode(id="approval", kind="approval", choices=["revise"], assignee="@owner")
    flow = Flow(id="f", name="Example", start="approval", nodes={"approval": paused})
    prior = store.FlowRun(run_id="run", flow_id="f", status="paused_approval", cursor="approval")
    kwargs = dict(submitted_inputs={"comment": "please revise"}, expired=False,
                  binding="decision-binding", expiry_binding="expiry-binding",
                  actor_matches=_approval_actor_matches)
    result = prepare_approval_decision(flow, prior, decision="revise", decided_by="user:owner", **kwargs)
    assert result.actor == "user:owner"
    assert result.binding == "decision-binding"
    assert result.resume_fields == {"decision": "revise"}
    with pytest.raises(ValueError, match="declared assignee"):
        prepare_approval_decision(flow, prior, decision="revise", decided_by="user:other", **kwargs)


def test_expiry_cannot_smuggle_a_human_decision_or_input():
    flow = Flow(id="f", name="Example", start="approval")
    prior = store.FlowRun(run_id="run", flow_id="f", status="paused_approval", cursor="approval")
    kwargs = dict(decision=None, decided_by="", expired=True, binding="decision-binding",
                  expiry_binding="expiry-binding", actor_matches=_approval_actor_matches)
    result = prepare_approval_decision(flow, prior, submitted_inputs={}, **kwargs)
    assert result.expired is True
    assert result.binding == "expiry-binding"
    assert result.resume_fields == {"expired": True}
    with pytest.raises(ValueError, match="expiry payload"):
        prepare_approval_decision(flow, prior, submitted_inputs={"answer": "yes"}, **kwargs)
