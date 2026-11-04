"""Learned scalar execution preserves agent fallback and flow authority boundaries."""
from __future__ import annotations

import json

import pytest
from maverick import audit, config, learning_guard
from maverick.audit.errors import AuditRefused
from maverick.budget import BudgetExceeded
from maverick.flow import Flow, FlowNode, evolve, execution, runner, store
from maverick.flow.ir import learned_operator_work_digest
from maverick.flow.learned_operator import synthesize
from maverick.killswitch import Halted


@pytest.fixture(scope="module")
def artifact():
    return synthesize(
        {"inputs": {"x": {"type": "integer", "min": 0, "max": 20}},
         "output_type": "integer", "constants": [0, 1]},
        [{"inputs": {"x": x}, "output": x} for x in (0, 2, 5)],
    )


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setattr(config, "get_flows", lambda: {"enable": True, "learned_operators": True})
    monkeypatch.setattr(learning_guard, "check_learning_halt", lambda *args: None)
    receipts = []

    def record(kind, **payload):
        receipts.append({"kind": kind, **payload})
        return True

    monkeypatch.setattr(audit, "record", record)
    return receipts


def _base() -> Flow:
    return Flow(id="pure-learning", name="Pure learning", start="calculate", nodes={
        "calculate": FlowNode(id="calculate", kind="agent", brief="Review {{x}}", output="answer"),
    })


def _attached(artifact) -> Flow:
    return evolve.attach_learned_operator(_base(), "calculate", artifact)


def _execute(flow, data, *, agent=None, on_node=None):
    calls = []

    def fallback(node, brief, values):
        calls.append((node.id, brief, dict(values)))
        return agent(node, brief, values) if agent else ("agent-answer", 1.0)

    def forbidden_action(*args):
        pytest.fail("pure scalar specialization must not dispatch tools")

    result = runner.run_flow(flow, data=data, agent_fn=fallback,
                             action_fn=forbidden_action, on_node=on_node)
    return result, calls


def test_attach_and_roundtrip_preserve_original_agent_and_independent_bytes(artifact):
    base = _base()
    attached = evolve.attach_learned_operator(base, "calculate", artifact)
    assert base.nodes["calculate"].learned_operator is None
    assert attached.nodes["calculate"].kind == "agent"
    assert attached.nodes["calculate"].brief == base.nodes["calculate"].brief
    assert attached.validate() == []
    restored = Flow.from_dict(json.loads(json.dumps(attached.to_dict())))
    assert restored.to_dict() == attached.to_dict()
    restored.nodes["calculate"].learned_operator["artifact"]["examples"][0]["output"] = 17
    assert attached.nodes["calculate"].learned_operator["artifact"] == artifact
    exported = attached.to_dict()
    exported["nodes"][0]["learned_operator"]["artifact"]["examples"][0]["output"] = 18
    assert attached.nodes["calculate"].learned_operator["artifact"] == artifact


@pytest.mark.parametrize("field,value", [("kind", "setvar"), ("brief", ""), ("output", "")])
def test_attach_rejects_missing_original_work_contract(artifact, field, value):
    flow = _base()
    setattr(flow.nodes["calculate"], field, value)
    with pytest.raises(ValueError, match="agent brief and output"):
        evolve.attach_learned_operator(flow, "calculate", artifact)


def test_agreement_skips_model_preserves_type_and_does_not_create_quality_label(artifact, enabled):
    outcomes = []
    result, calls = _execute(_attached(artifact), {"x": 3}, on_node=lambda *row: outcomes.append(row))
    assert result.status == "completed"
    assert result.data["answer"] == 3 and type(result.data["answer"]) is int
    assert calls == []
    assert outcomes[-1][1:] == ("done", None)
    assert enabled[-1]["status"] == "applied"
    assert enabled[-1]["reason"] == "agreement"
    assert enabled[-1]["artifact_sha256"] == artifact["artifact_sha256"]
    assert enabled[-1]["flow_id"] == "pure-learning"
    assert enabled[-1]["flow_run_id"] == ""
    assert set(enabled[-1]) == {"kind", "agent", "flow_id", "flow_run_id", "node_id", "status", "reason",
                                "artifact_sha256", "work_sha256", "candidate_count"}


@pytest.mark.parametrize("value", [True, "3", -1, 21, None])
def test_strict_type_and_domain_failures_fall_back_once(artifact, enabled, value):
    result, calls = _execute(_attached(artifact), {"x": value})
    assert result.status == "completed" and result.data["answer"] == "agent-answer"
    assert len(calls) == 1
    assert enabled[-1]["status"] == "fallback"
    assert enabled[-1]["reason"] == "outside_domain"


def test_ambiguous_examples_cause_fallback_on_a_distinguishing_input(enabled):
    artifact = synthesize(
        {"inputs": {key: {"type": "integer", "min": 0, "max": 10} for key in ("x", "y")},
         "output_type": "integer", "constants": []},
        [{"inputs": {"x": x, "y": x}, "output": x} for x in (1, 2)],
    )
    result, calls = _execute(_attached(artifact), {"x": 3, "y": 4})
    assert result.status == "completed" and len(calls) == 1
    assert enabled[-1]["reason"] == "ambiguity"


@pytest.mark.parametrize("setting", [False, "true", 1, None])
def test_feature_requires_literal_true(artifact, enabled, monkeypatch, setting):
    monkeypatch.setattr(config, "get_flows", lambda: {"learned_operators": setting})
    _, calls = _execute(_attached(artifact), {"x": 3})
    assert len(calls) == 1
    assert enabled[-1]["reason"] == "feature_disabled"


def test_flow_master_switch_disables_specialization(artifact, enabled, monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOWS", "0")
    _, calls = _execute(_attached(artifact), {"x": 3})
    assert len(calls) == 1
    assert enabled[-1]["reason"] == "feature_disabled"


@pytest.mark.parametrize("field,value", [("brief", "A new task"), ("output", "different"),
                                        ("timeout", 1.0), ("retries", 1)])
def test_original_work_change_cannot_silently_retain_operator(artifact, enabled, field, value):
    flow = _attached(artifact)
    setattr(flow.nodes["calculate"], field, value)
    assert any("learned operator" in error for error in flow.validate())
    result, calls = _execute(flow, {"x": 3})
    assert result.status == "completed" and len(calls) == 1
    assert enabled[-1]["reason"] == "work_changed"


def test_corrupt_candidate_is_never_executed_and_is_not_a_raw_audit_payload(artifact, enabled):
    flow = _attached(artifact)
    flow.nodes["calculate"].learned_operator["artifact"]["examples"][0]["output"] = "PRIVATE-EXAMPLE"
    assert flow.validate()
    result, calls = _execute(flow, {"x": 3, "unrelated": "PRIVATE-INPUT"})
    assert result.status == "completed" and len(calls) == 1
    assert enabled[-1]["reason"] == "invalid_artifact"
    assert "PRIVATE" not in json.dumps(enabled)


@pytest.mark.parametrize("receipt", [False, None, 1])
def test_missing_durable_receipt_blocks_both_fast_path_and_fallback(artifact, enabled, monkeypatch, receipt):
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: receipt)
    for value in (3, 21):
        with pytest.raises(AuditRefused, match="durable audit receipt"):
            _execute(_attached(artifact), {"x": value},
                     agent=lambda *args: pytest.fail("audit refusal cannot fall back"))


@pytest.mark.parametrize("exception", [AuditRefused("required audit denied"), OSError("sink unavailable")])
def test_audit_exception_remains_a_control_stop_inside_scope(artifact, enabled, monkeypatch, exception):
    def refuse(*args, **kwargs):
        raise exception

    monkeypatch.setattr(audit, "record", refuse)
    body = _attached(artifact)
    flow = Flow(id="scope", name="Scope", start="try", nodes={
        "try": FlowNode(id="try", kind="scope", body=body, on_error="recover"),
        "recover": FlowNode(id="recover", kind="agent", brief="Do something else"),
    })
    with pytest.raises(AuditRefused, match="audit"):
        _execute(flow, {"x": 3}, agent=lambda *args: pytest.fail("scope cannot recover audit refusal"))


@pytest.mark.parametrize("exception", [Halted("stopped", "test"), BudgetExceeded("budget")])
def test_learning_control_stops_propagate_without_agent_fallback(artifact, enabled, monkeypatch, exception):
    def halt(*args):
        raise exception

    monkeypatch.setattr(learning_guard, "check_learning_halt", halt)
    with pytest.raises(type(exception)):
        _execute(_attached(artifact), {"x": 3}, agent=lambda *args: pytest.fail("halt must not fall back"))
    assert enabled == []


@pytest.mark.parametrize("phase", ["receipt", "dispatch"])
def test_halt_during_selection_blocks_dispatch(artifact, enabled, monkeypatch, phase):
    def halt(job, current_phase):
        if current_phase == phase:
            raise Halted("operator stopped during selection", "test")

    monkeypatch.setattr(learning_guard, "check_learning_halt", halt)
    with pytest.raises(Halted):
        _execute(_attached(artifact), {"x": 3}, agent=lambda *args: pytest.fail("halt must not dispatch"))
    assert len(enabled) == (1 if phase == "dispatch" else 0)


def test_fallback_effect_failure_is_never_replayed(artifact, enabled):
    calls = []

    def agent(*args):
        calls.append("effect")
        raise RuntimeError("response lost after effect")

    result, _ = _execute(_attached(artifact), {"x": 30}, agent=agent)
    assert result.status == "indeterminate"
    assert calls == ["effect"]


def test_remove_swap_and_revert_track_operator_work_identity(artifact):
    attached = _attached(artifact)
    removed = evolve.remove_learned_operator(attached, "calculate")
    assert removed.nodes["calculate"].learned_operator is None
    assert attached.nodes["calculate"].learned_operator is not None
    assert not evolve.same_work_definition(attached.nodes["calculate"], removed.nodes["calculate"])
    restored = evolve.revert_node(removed, "calculate", attached.nodes["calculate"])
    assert evolve.same_work_definition(attached.nodes["calculate"], restored.nodes["calculate"])
    changed_output = removed.copy()
    changed_output.nodes["calculate"].output = "changed"
    restored = evolve.revert_node(changed_output, "calculate", attached.nodes["calculate"])
    assert restored.nodes["calculate"].learned_operator is None
    swapped = evolve.apply_proposal(attached, "calculate", "action", tool="web_search", params={"query": "x"})
    assert swapped.nodes["calculate"].learned_operator is None


def test_flow_snapshot_pins_operator_even_when_draft_is_removed(artifact, tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.paths.data_dir", lambda *parts, **kwargs: tmp_path.joinpath(*parts))
    attached = _attached(artifact)
    digest, _, _ = store.snapshot_flow_bundle(attached)
    removed = evolve.remove_learned_operator(attached, "calculate")
    second_digest, _, _ = store.snapshot_flow_bundle(removed)
    assert digest != second_digest
    pinned = store.load_flow_snapshot(digest)
    assert pinned.nodes["calculate"].learned_operator == attached.nodes["calculate"].learned_operator
    assert pinned.nodes["calculate"].learned_operator["work_sha256"] == learned_operator_work_digest(pinned.nodes["calculate"])
    assert pinned.nodes["calculate"].learned_operator["artifact"] == artifact


@pytest.mark.parametrize("value,status,reason", [(3, "applied", "agreement"), (21, "fallback", "outside_domain")])
def test_native_signed_receipt_is_durable_and_contains_only_decision_metadata(artifact, monkeypatch, value, status, reason):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setattr(config, "get_flows", lambda: {"learned_operators": True})
    result, calls = _execute(_attached(artifact), {"x": value, "unrelated": "PRIVATE-INPUT"})
    assert result.status == "completed"
    assert len(calls) == (1 if status == "fallback" else 0)
    events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    decisions = [event for event in events if event["kind"] == audit.EventKind.FLOW_LEARNED_OPERATOR_DECISION]
    assert len(decisions) == 1
    assert decisions[0]["flow_id"] == "pure-learning"
    assert decisions[0]["flow_run_id"] == ""
    assert decisions[0]["node_id"] == "calculate"
    assert decisions[0]["artifact_sha256"] == artifact["artifact_sha256"]
    assert decisions[0]["status"] == status
    assert decisions[0]["reason"] == reason
    assert decisions[0]["sig"]
    assert "PRIVATE-INPUT" not in json.dumps(events)


def test_durable_execution_attributes_nested_and_parallel_receipts_to_persisted_run(artifact, monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setattr(config, "get_flows", lambda: {"learned_operators": True})
    left = _attached(artifact)
    left.id = "nested-left"
    right = _attached(artifact)
    right.id = "nested-right"
    body = Flow(id="parallel-body", name="Parallel", start="branches", nodes={
        "branches": FlowNode(id="branches", kind="parallel", branches=[left, right]),
    })
    flow = Flow(id="attributed-root", name="Attribution", start="scope", nodes={
        "scope": FlowNode(id="scope", kind="scope", body=body),
    })

    def forbidden_executor(*args, **kwargs):
        pytest.fail("learned agreement must not dispatch an agent or tool")

    run = execution.execute(flow, agent_runner=forbidden_executor, action_runner=forbidden_executor,
                            data={"x": 3})
    assert run.status == "completed" and run.run_id
    saved = store.load_run(run.run_id)
    assert saved is not None and saved.run_id == run.run_id and saved.flow_id == flow.id
    events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    decisions = [event for event in events if event["kind"] == audit.EventKind.FLOW_LEARNED_OPERATOR_DECISION]
    assert len(decisions) == 2
    assert {event["flow_id"] for event in decisions} == {"nested-left", "nested-right"}
    assert {event["flow_run_id"] for event in decisions} == {saved.run_id}
    assert all(event["node_id"] == "calculate" and event["sig"] for event in decisions)
