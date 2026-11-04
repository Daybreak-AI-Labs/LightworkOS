"""Durable workflow plans retain graph identity and execution authority."""
import pytest
from maverick.flow import store
from maverick.flow.execution_plan import ExecutionPlan, bind_execution_plan, pin_new_plan
from maverick.flow.ir import Flow, FlowNode


def _flow(flow_id="f"):
    node = FlowNode(id="work", kind="setvar", assignments={"value": "ready"})
    return Flow(id=flow_id, name="Example", start="work", nodes={"work": node})


def test_saved_plan_cannot_bind_a_different_flow_identity(monkeypatch):
    prior = store.FlowRun(run_id="run", flow_id="original", status="paused_delay",
                          definition_digest="saved", subflow_digests={"child": "digest"})
    owners = []
    monkeypatch.setattr(store, "validate_snapshot_bundle_owners", lambda *args: owners.append(args))
    with pytest.raises(store.FlowSnapshotError, match="identity"):
        bind_execution_plan(_flow("other"), prior=prior, placeholder=None)
    assert owners == []


def test_queued_plan_restores_saved_graph_and_authority(monkeypatch):
    queued = store.FlowRun(run_id="run", flow_id="f", status="queued", definition_digest="saved",
                           release_digest="bundle", release_id="release", definition_version=4,
                           execution_user_id="user:alice", execution_channel="dashboard",
                           allowed_suites=["finance"], subflow_digests={"child": "child-digest"})
    saved = _flow()
    owners = []
    monkeypatch.setattr(store, "load_flow_snapshot", lambda digest: saved)
    monkeypatch.setattr(store, "validate_snapshot_bundle_owners", lambda *args: owners.append(args))
    plan = bind_execution_plan(_flow("edited"), prior=None, placeholder=queued)
    assert plan.flow is saved
    assert plan.definition_digest == "saved"
    assert plan.release_id == "release"
    assert plan.execution_user_id == "user:alice"
    assert plan.allowed_suites == ["finance"]
    assert owners == [(saved, {"child": "child-digest"})]


def test_pinned_plan_is_never_resnapshotted(monkeypatch):
    def must_not_snapshot(_flow):
        raise AssertionError("immutable plan was replaced")

    monkeypatch.setattr(store, "snapshot_flow_bundle", must_not_snapshot)
    plan = ExecutionPlan(flow=_flow(), definition_digest="saved", pinned=True)
    assert pin_new_plan(plan) is plan
