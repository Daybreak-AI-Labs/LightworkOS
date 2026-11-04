"""Packed operators use the existing guarded flow and reviewed-draft lifecycle."""
from __future__ import annotations

import hashlib
import json

import pytest
from maverick import audit, config, crypto_at_rest, governed_records, learning_guard
from maverick.audit.errors import AuditRefused
from maverick.flow import Flow, FlowNode, evolve, runner, store
from maverick.flow import composed_operator as composed
from maverick.flow import learned_operator as scalar
from maverick.flow import operator_artifacts as artifacts
from maverick.flow import operator_queries as queries
from maverick.flow.operator_review import OperatorReviewService
from maverick.governed_operations import ServiceContext
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope


@pytest.fixture(scope="module")
def packed():
    return composed.synthesize(
        {"inputs": {"code": {"type": "string", "max_length": 30}}, "output_type": "string"},
        [{"inputs": {"code": " a "}, "output": "A"},
         {"inputs": {"code": " b "}, "output": "B"}],
        max_operations=2, operators=["strip", "upper"],
    )


def _ambiguous():
    return composed.synthesize(
        {"inputs": {"code": {"type": "string", "max_length": 30}}, "output_type": "string"},
        [{"inputs": {"code": "a"}, "output": "A"},
         {"inputs": {"code": "b"}, "output": "B"}],
        max_operations=2, operators=["strip", "upper"],
    )


def _flow(artifact, *, owner=""):
    return evolve.attach_learned_operator(Flow(id="composed", name="Normalize codes", owner=owner,
        start="normalize", nodes={"normalize": FlowNode(id="normalize", kind="agent",
        brief="Normalize the supplied code", output="answer")}), "normalize", artifact)


def test_scalar_artifact_bytes_and_dispatch_decisions_are_unchanged():
    old = scalar.synthesize(
        {"inputs": {"x": {"type": "integer", "min": 0, "max": 20}},
         "output_type": "integer", "constants": [1]},
        [{"inputs": {"x": 2}, "output": 3}, {"inputs": {"x": 7}, "output": 8}],
    )
    raw = scalar._canonical(old)
    restored = artifacts.validated_artifact(old)
    assert scalar._canonical(restored) == raw
    assert restored is not old
    for x in (0, 10, 20, 21, True):
        assert artifacts.evaluate(restored, {"x": x}) == scalar.evaluate(old, {"x": x})
    assert artifacts.candidate_count(old) == len(old["candidates"])
    assert artifacts.evaluation_cost(old) == len(old["candidates"])
    assert artifacts.partitions(old, {"x": 10}) == [{"output": 11, "candidate_count": len(old["candidates"])}]
    assert artifacts.partitions(old, {"x": True}) is None


def test_packed_attachment_roundtrip_preserves_schema_and_original_agent(packed):
    attached = _flow(packed)
    assert "candidates" not in packed
    assert attached.validate() == []
    restored = Flow.from_dict(json.loads(json.dumps(attached.to_dict())))
    assert restored.to_dict() == attached.to_dict()
    node = restored.nodes["normalize"]
    assert node.kind == "agent" and node.brief == "Normalize the supplied code"
    assert node.learned_operator["artifact"]["schema"] == composed.SCHEMA
    removed = evolve.remove_learned_operator(restored, "normalize")
    assert removed.nodes["normalize"].learned_operator is None
    assert attached.nodes["normalize"].learned_operator["artifact"] == packed


@pytest.fixture
def execution_enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setattr(config, "get_flows", lambda: {"learned_operators": True, "composed_operators": True})
    monkeypatch.setattr(learning_guard, "check_learning_halt", lambda *a: None)
    receipts = []

    def record(kind, **payload):
        receipts.append(payload)
        return True

    monkeypatch.setattr(audit, "record", record)
    return receipts


def _execute(artifact, code):
    fallback = []
    outcomes = []

    def agent(*args):
        fallback.append(args)
        return "fallback-result", 1.0

    result = runner.run_flow(_flow(artifact), data={"code": code}, agent_fn=agent,
                            action_fn=lambda *a: pytest.fail("pure operator dispatched a tool"),
                            on_node=lambda *row: outcomes.append(row))
    return result, fallback, outcomes


def test_packed_agreement_runs_without_agent_or_grounded_success(packed, execution_enabled):
    result, fallback, outcomes = _execute(packed, " c ")
    assert result.status == "completed" and result.data["answer"] == "C"
    assert fallback == [] and outcomes[-1][1:] == ("done", None)
    receipt = execution_enabled[-1]
    assert receipt["reason"] == "agreement"
    assert receipt["candidate_count"] == artifacts.candidate_count(packed)
    assert receipt["artifact_sha256"] == packed["artifact_sha256"]
    assert "inputs" not in receipt and "output" not in receipt


@pytest.mark.parametrize("setting", [False, "true", 1, None])
def test_packed_gate_requires_literal_true(packed, execution_enabled, monkeypatch, setting):
    monkeypatch.setattr(config, "get_flows", lambda: {"learned_operators": True, "composed_operators": setting})
    result, fallback, _ = _execute(packed, " c ")
    assert result.data["answer"] == "fallback-result" and len(fallback) == 1
    assert execution_enabled[-1]["reason"] == "feature_disabled"


def test_composed_opt_in_does_not_enable_scalar_execution(packed, execution_enabled, monkeypatch):
    monkeypatch.setattr(config, "get_flows", lambda: {"learned_operators": False, "composed_operators": True})
    _, fallback, _ = _execute(packed, " c ")
    assert len(fallback) == 1 and execution_enabled[-1]["reason"] == "feature_disabled"


def test_packed_ambiguity_and_domain_errors_use_original_agent(execution_enabled):
    artifact = _ambiguous()
    for code, reason in [(" c ", "ambiguity"), (True, "outside_domain")]:
        _, fallback, _ = _execute(artifact, code)
        assert len(fallback) == 1 and execution_enabled[-1]["reason"] == reason


def test_evaluation_limit_is_truthful_fallback_reason(packed, execution_enabled, monkeypatch):
    monkeypatch.setattr(composed, "evaluate", lambda artifact, data:
        scalar.Decision(False, reason="evaluation_limit", artifact_digest=artifact["artifact_sha256"],
                        candidate_count=artifacts.candidate_count(artifact)))
    _, fallback, _ = _execute(packed, " c ")
    assert len(fallback) == 1 and execution_enabled[-1]["reason"] == "evaluation_limit"


def test_packed_missing_receipt_blocks_fast_path_and_fallback(packed, execution_enabled, monkeypatch):
    monkeypatch.setattr(audit, "record", lambda *a, **k: None)
    for code in (" c ", True):
        with pytest.raises(AuditRefused, match="durable audit receipt"):
            _execute(packed, code)


def test_questions_partition_and_refine_packed_candidates():
    artifact = _ambiguous()
    before = scalar._canonical(artifact)
    question = queries.propose_question(artifact, max_probes=32)
    assert question["status"] == "found"
    assert question["candidate_count"] == artifacts.candidate_count(artifact)
    assert sum(p["candidate_count"] for p in question["predictions"]) == question["candidate_count"]
    assert question["predictions"] == artifacts.partitions(artifact, question["inputs"])
    selected = question["inputs"]["code"].strip().upper()
    refined = queries.answer_question(artifact, question, selected)
    assert refined["schema"] == composed.SCHEMA
    assert artifacts.candidate_count(refined) < artifacts.candidate_count(artifact)
    assert artifacts.evaluate(refined, question["inputs"]).value == selected
    assert scalar._canonical(artifact) == before


def test_question_budget_uses_packed_cost_not_candidate_count(monkeypatch):
    artifact = _ambiguous()
    queries._proposal.cache_clear()
    monkeypatch.setattr(composed, "evaluation_cost", lambda artifact: queries.MAX_EVALUATIONS // 2)
    question = queries.propose_question(artifact, max_probes=32)
    assert question["coverage"]["effective_probe_budget"] == 2
    assert question["coverage"]["examined"] <= 2
    queries._proposal.cache_clear()


def test_cost_exceeding_total_budget_performs_no_probes(packed, monkeypatch):
    queries._proposal.cache_clear()
    monkeypatch.setattr(composed, "evaluation_cost", lambda artifact: queries.MAX_EVALUATIONS + 1)
    monkeypatch.setattr(composed, "partitions", lambda *a: pytest.fail("query exceeded evaluation budget"))
    question = queries.propose_question(packed, max_probes=32)
    assert question["status"] == "search_exhausted"
    assert question["coverage"]["effective_probe_budget"] == 0
    assert question["coverage"]["examined"] == 0
    assert question["coverage"]["complete"] is False
    queries._proposal.cache_clear()


def test_incomplete_packed_partition_cannot_claim_equivalence(monkeypatch):
    artifact = composed.synthesize({"inputs": {"x": {"type": "boolean"}}, "output_type": "boolean"},
        [{"inputs": {"x": False}, "output": True}, {"inputs": {"x": True}, "output": False}],
        max_operations=1, operators=["not"])
    queries._proposal.cache_clear()
    monkeypatch.setattr(composed, "partitions", lambda *a: None)
    question = queries.propose_question(artifact)
    assert question["status"] == "search_exhausted"
    assert question["coverage"]["invalid_probes"] == 2
    assert question["coverage"]["complete"] is False
    queries._proposal.cache_clear()


def test_packed_governed_review_exports_only_an_unpublished_refined_draft(tmp_path, monkeypatch):
    crypto_at_rest._reset_shared_key_identity_for_testing()
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    # The review export verifies signed audit receipts; pin signing so the test
    # holds under the suite's ordinary posture as well as the secure one.
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    for name in ("MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_PG_DSN",
                 "MAVERICK_REPLICA_COUNT", "MAVERICK_WORLD_BACKEND"):
        monkeypatch.delenv(name, raising=False)
    key = b"c" * 32
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", "sha256:" + hashlib.sha256(key).hexdigest())
    monkeypatch.setattr(config, "get_flows", lambda: {"learned_operator_questions": True})
    ctx = ServiceContext(tenant="composed-review", actor="alice", resource_owner="alice",
                         credential_authority="none", credential_ref="none", human=True)
    try:
        with tenant_scope(tenant=ctx.tenant):
            original = store.save_flow(_flow(_ambiguous(), owner="alice"))
        before = original.to_dict()
        service = OperatorReviewService(lambda *a: True,
            records=GovernedRecordStore("flow_operator_reviews", "LOQ", "flow_operator_review"))
        row = service.request(ctx, original.id, "normalize", expected_flow_version=original.version,
                              expected_flow_revision=original.revision, max_probes=32)
        output = row["question"]["inputs"]["code"].strip().upper()
        answered = service.answer(ctx, row["id"], output, expected_revision=row["revision"],
                                  rationale="Reviewed the intended code normalization")
        assert answered["status"] == "draft_ready"
        assert answered["lineage"]["candidates_after"] < answered["lineage"]["candidates_before"]
        draft = service.export_draft(ctx, row["id"])
        assert draft.to_dict() == answered["draft"]
        assert draft.nodes["normalize"].learned_operator["artifact"]["schema"] == composed.SCHEMA
        with tenant_scope(tenant=ctx.tenant):
            assert store.load_flow(original.id).to_dict() == before
            assert store.load_published_bundle(original.id) is None
            events = list(audit.iter_events(all_days=True, strict=True, verify=True))
        events = [e for e in events if e.get("record_type") == "flow_operator_review"]
        assert [e["action"] for e in events] == ["operator_question_requested", "operator_question_answered"]
        assert all("inputs" not in e and "output" not in e for e in events)
    finally:
        crypto_at_rest._reset_shared_key_identity_for_testing()
        governed_records._reset_process_authority_pin_for_testing()
