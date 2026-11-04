"""Actual governed native executions of learned variable-length procedures."""
from __future__ import annotations

import copy
import multiprocessing

import pytest
from maverick import audit, world_model
from maverick.approval_cards import ApprovalCardError
from maverick.audit.errors import AuditRefused
from maverick.flow import execution, recipe_flow, store
from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
from maverick.flow.workflow_recipe_flow import HISTORY, SELECTION
from maverick_dashboard.approval_authority import issue_flow_decision_attestation

from test_support.action_episode_native import _no_agent
from test_support.action_episode_native import native as native
from test_support.audit_child_process import audit_signing_target
from test_support.workflow_runtime_native import child_resume
from test_support.workflow_transducer_native import workflow_native as workflow_native

INPUTS = {"customer": "unseen-customer", "quantity": 5, "repeat": False}


def decide(run_id, *, decision="approved", inputs=None, authenticated=True, action_runner=None):
    run = store.load_run(run_id, owner="reviewer")
    binding = paused_operation_binding(run, inputs=inputs)
    material = flow_decision_attestation_material(run, inputs=inputs, operation_binding_sha256=binding,
        authority_binding_sha256="", decision=decision, decided_by="reviewer")
    token = issue_flow_decision_attestation(None, material=material,
        expires_at=float(run.human["approval_card"]["expires_at"])) if authenticated else None
    return execution.execute(store.load_flow_snapshot(run.definition_digest), owner="reviewer",
        resume_run_id=run_id, decision=decision, decided_by="reviewer", inputs=inputs,
        approval_binding_sha256=binding, approval_decision_attestation=token,
        agent_runner=_no_agent, action_runner=action_runner or execution.default_action_runner(None, user_id="reviewer"))


def redeliver(run_id):
    run = store.load_run(run_id, owner="reviewer")
    return execution.execute(store.load_flow_snapshot(run.definition_digest), owner="reviewer",
        run_id=run_id, agent_runner=_no_agent,
        action_runner=execution.default_action_runner(None, user_id="reviewer"))


@pytest.mark.parametrize("repeat,length", [(False, 2), (True, 3)])
def test_learned_path_and_completion_each_require_own_approval(workflow_native, repeat, length):
    env = workflow_native
    flow = env.draft("learned-procedure")
    assert not flow.validate(), flow.validate()
    before = env.counts()
    run = env.start(flow, {**INPUTS, "repeat": repeat})
    assert run.status == "paused_approval" and run.cursor == "approval_0_0", run.error
    assert env.counts() == before
    for index in range(length):
        assert run.data[SELECTION]["step_index"] == index
        assert len(run.data[HISTORY]) == index
        run = decide(run.run_id)
        assert env.counts() == before + index + 1
        assert run.status == ("completed" if index + 1 == length else "paused_approval"), run.error
    assert run.data[SELECTION]["kind"] == "complete"
    assert len(run.data[HISTORY]) == length and "_recipe_next_arguments" not in run.data
    assert env.calls()[before:][1]["arguments"] == {"customer_id": "C42", "quantity": 5}
    assert redeliver(run.run_id).status == "completed" and env.counts() == before + length
    events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
              if event.get("flow_run_id") == run.run_id and event["kind"] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION]
    decisions = [event for event in events if event.get("status") == "workflow_selected"]
    assert len(decisions) == length + 1
    assert decisions[-1]["recipe_workflow"]["kind"] == "complete"
    assert all(event.get("sig") and event["recipe_workflow"]["history_sha256"] for event in events)
    assert all("unseen-customer" not in str(event) for event in events)


def test_initial_and_resume_values_cannot_inject_completed_work(workflow_native):
    env = workflow_native
    flow = env.draft("untrusted-procedure")
    forged = {HISTORY: [{"tool": "episode_update", "arguments": {}, "result": {}}],
              SELECTION: {"kind": "complete"}, "_recipe_step_0": {"customer_id": "stolen"}}
    run = execution.execute(flow, owner="reviewer", data={"input": INPUTS, **forged}, agent_runner=_no_agent,
        action_runner=execution.default_action_runner(None, user_id="reviewer"))
    assert run.status == "paused_approval" and run.data[HISTORY] == []
    assert "_recipe_step_0" not in run.data
    before = env.counts()
    run = decide(run.run_id, inputs=forged)
    assert run.status == "paused_approval" and len(run.data[HISTORY]) == 1, run.error
    run = decide(run.run_id, inputs=forged)
    assert run.status == "completed" and env.counts() == before + 2, run.error
    assert run.data[HISTORY][0]["result"]["customer_id"] == "C42"


def test_unsigned_approval_and_rejection_do_not_dispatch(workflow_native):
    env = workflow_native
    run = env.start(env.draft("approval-procedure"), INPUTS)
    before = env.counts()
    with pytest.raises(ApprovalCardError, match="attestation"):
        decide(run.run_id, authenticated=False)
    assert store.load_run(run.run_id).status == "paused_approval" and env.counts() == before
    run = decide(run.run_id)
    assert run.status == "paused_approval" and env.counts() == before + 1
    assert decide(run.run_id, decision="rejected").status == "rejected"
    assert redeliver(run.run_id).status == "rejected" and env.counts() == before + 1


@pytest.mark.parametrize("status,index", [("workflow_selected", 1), ("selected", 1), ("workflow_selected", 2)])
def test_feature_withdrawal_after_receipt_stops_next_effect_or_completion(workflow_native, monkeypatch, status, index):
    env = workflow_native
    run = env.start(env.draft("withdraw-procedure"), INPUTS)
    if status == "selected" or index == 2:
        run = decide(run.run_id)
    before = env.counts()
    original = audit.record
    seen = []

    def record(*args, **kwargs):
        receipt = original(*args, **kwargs)
        if (args and args[0] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION
                and kwargs.get("flow_run_id") == run.run_id
                and kwargs.get("status") == status and kwargs.get("step_index") == index):
            env.flags["action_workflow_learning"] = False
            seen.append(True)
        return receipt

    monkeypatch.setattr(audit, "record", record)
    stopped = decide(run.run_id)
    assert seen and stopped.status in {"failed", "indeterminate"}, stopped.error
    assert env.counts() == before + (status == "workflow_selected")
    assert len(stopped.data[HISTORY]) == index


def test_no_lineage_and_graph_edits_cannot_be_persisted(workflow_native):
    env = workflow_native
    raw = recipe_flow.make_flow(env.package["artifact"], flow_id="unsigned-workflow", name="Unsigned")
    raw.owner = "reviewer"
    with pytest.raises(ValueError, match="admitted signed evidence"):
        store.save_flow(raw)
    flow = env.draft("exact-workflow")
    for mutate in (lambda f: setattr(f.nodes["action_0_0"], "next", None),
                   lambda f: setattr(f.nodes["action_0_0"], "retries", 1),
                   lambda f: setattr(f, "start", "action_0_0")):
        changed = copy.deepcopy(flow)
        mutate(changed)
        with pytest.raises(ValueError, match="graph changed|nodes changed"):
            store.save_flow(changed)


def test_withdrawn_review_blocks_continuation_after_real_prefix(workflow_native):
    env = workflow_native
    run = env.start(env.draft("source-withdrawal-workflow"), INPUTS)
    run = decide(run.run_id)
    assert run.status == "paused_approval" and len(run.data[HISTORY]) == 1
    before = env.counts()
    body = env.package["bundles"][0]["body"]
    source = body["source"]
    row = env.service.get(env.context, source["flow_id"], source["run_id"])
    env.service.withdraw(env.context, source["flow_id"], source["run_id"], expected_revision=row["revision"],
        expected_episode_sha256=row["episode_sha256"], expected_review_sha256=body["review_sha256"],
        rationale="Withdraw source before a learned native continuation")
    stopped = decide(run.run_id)
    assert stopped.status in {"failed", "indeterminate"} and env.counts() == before, stopped.error
    assert len(stopped.data[HISTORY]) == 1
    assert redeliver(run.run_id).status == stopped.status and env.counts() == before


@pytest.mark.parametrize("status", ["workflow_selected", "completed"])
def test_posteffect_receipt_failure_quarantines_without_replay(workflow_native, monkeypatch, status):
    env = workflow_native
    run = env.start(env.draft("receipt-workflow"), INPUTS)
    before = env.counts()
    original = audit.record

    def record(*args, **kwargs):
        receipt = original(*args, **kwargs)
        if (args and args[0] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION
                and kwargs.get("flow_run_id") == run.run_id and kwargs.get("status") == status):
            return 1
        return receipt

    with monkeypatch.context() as boundary:
        boundary.setattr(audit, "record", record)
        with pytest.raises(AuditRefused):
            decide(run.run_id)
    assert env.counts() == before + 1
    assert store.load_run(run.run_id).status == "indeterminate"
    assert redeliver(run.run_id).status == "indeterminate" and env.counts() == before + 1


def test_lost_mutation_response_preserves_prefix_and_never_repeats_update(workflow_native):
    env = workflow_native
    run = env.start(env.draft("lost-response-workflow"), INPUTS)
    run = decide(run.run_id)
    assert run.status == "paused_approval"
    before = env.counts()
    original = execution.default_action_runner(None, user_id="reviewer")

    def lose_response(node, params, data):
        original(node, params, data)
        raise ConnectionError("simulated acknowledgement loss after native effect")

    run = decide(run.run_id, action_runner=lose_response)
    assert run.status == "indeterminate" and env.counts() == before + 1, run.error
    assert len(run.data[HISTORY]) == 1
    assert redeliver(run.run_id).status == "indeterminate" and env.counts() == before + 1


def test_fresh_worker_continues_variable_path_without_prefix_replay(workflow_native):
    env = workflow_native
    before = env.counts()
    run = env.start(env.draft("fresh-worker-workflow"), {**INPUTS, "repeat": True})
    run = decide(run.run_id)
    assert run.status == "paused_approval" and env.counts() == before + 1
    process = multiprocessing.get_context("spawn").Process(target=audit_signing_target(child_resume),
        args=(run.run_id, str(env.journal), str(world_model.DEFAULT_DB), copy.deepcopy(env.flags)))
    process.start()
    process.join(45)
    if process.is_alive():
        process.terminate()
        process.join(5)
        pytest.fail("fresh worker did not resume the learned native workflow")
    assert process.exitcode == 0
    run = store.load_run(run.run_id, owner="reviewer")
    assert run.status == "paused_approval" and len(run.data[HISTORY]) == 2
    assert env.counts() == before + 2
    run = decide(run.run_id)
    assert run.status == "completed" and env.counts() == before + 3, run.error
