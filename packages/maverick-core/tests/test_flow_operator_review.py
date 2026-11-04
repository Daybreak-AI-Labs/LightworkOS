"""Durable reviewed questions remain tenant-bound and cannot activate a flow."""
from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from maverick import audit, config, crypto_at_rest, governed_records, learning_guard
from maverick.flow import Flow, FlowNode, store
from maverick.flow.evolve import attach_learned_operator
from maverick.flow.learned_operator import synthesize
from maverick.flow.operator_review import (
    MAX_RECORDS,
    OperatorReviewAuditPending,
    OperatorReviewConflict,
    OperatorReviewService,
)
from maverick.governed_operations import ServiceContext, digest
from maverick.governed_records import GovernedRecordStore, RecordConflict
from maverick.killswitch import Halted
from maverick.paths import tenant_scope


@pytest.fixture(autouse=True)
def isolated_review(tmp_path, monkeypatch):
    crypto_at_rest._reset_shared_key_identity_for_testing()
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    # The receipts these tests verify are signed; pin signing so they hold under
    # the suite's ordinary posture as well as the secure one.
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    for name in ("MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_PG_DSN",
                 "MAVERICK_REPLICA_COUNT", "MAVERICK_WORLD_BACKEND"):
        monkeypatch.delenv(name, raising=False)
    key = b"r" * 32
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", "sha256:" + hashlib.sha256(key).hexdigest())
    monkeypatch.setattr(config, "get_flows", lambda: {"learned_operator_questions": True})
    yield
    crypto_at_rest._reset_shared_key_identity_for_testing()
    governed_records._reset_process_authority_pin_for_testing()


def _context(**kwargs):
    base = ServiceContext(tenant="review-tenant", actor="reviewer:one", resource_owner="reviewer:one",
                          credential_authority="none", credential_ref="none", human=True)
    return replace(base, **kwargs)


def _save_flow(ctx, *, owner=None, ambiguous=True):
    keys = ("x", "y") if ambiguous else ("x",)
    artifact = synthesize(
        {"inputs": {key: {"type": "boolean"} for key in keys}, "output_type": "boolean"},
        [{"inputs": dict.fromkeys(keys, value), "output": value} for value in (False, True)],
    )
    flow = Flow(id="reviewed-flow", name="Reviewed flow", start="select", owner=ctx.resource_owner if owner is None else owner,
                nodes={"select": FlowNode(id="select", kind="agent", brief="Select the reviewed result", output="answer")})
    flow = attach_learned_operator(flow, "select", artifact)
    with tenant_scope(tenant=ctx.tenant):
        return store.save_flow(flow)


def _service(authorize=None):
    return OperatorReviewService(authorize or (lambda *args: True), records=GovernedRecordStore(
        "flow_operator_reviews", "LOQ", "flow_operator_review"), clock=lambda: 1234.0)


def _request(service, ctx, flow, **kwargs):
    return service.request(ctx, flow.id, "select", expected_flow_version=flow.version,
                           expected_flow_revision=flow.revision, **kwargs)


def _answer(service, ctx, row, **kwargs):
    return service.answer(ctx, row["id"], row["question"]["predictions"][0]["output"],
                          expected_revision=row["revision"], rationale="Reviewed expected scalar result", **kwargs)


def test_request_answer_export_persists_exact_lineage_without_saving_or_publishing():
    ctx, service = _context(), _service()
    original = _save_flow(ctx)
    before = original.to_dict()
    row = _request(service, ctx, original)
    assert row["status"] == "awaiting_answer" and row["audit_status"] == "delivered"
    assert row["binding"]["flow_sha256"] == digest(before)
    answered = _answer(service, ctx, row)
    assert answered["status"] == "draft_ready" and answered["revision"] == row["revision"] + 1
    assert answered["lineage"]["parent_artifact_sha256"] == row["binding"]["artifact_sha256"]
    assert answered["lineage"]["candidates_after"] < answered["lineage"]["candidates_before"]
    restored_service = _service()
    draft = restored_service.export_draft(ctx, row["id"])
    assert draft.to_dict() == answered["draft"]
    assert draft.version == original.version and draft.revision == original.revision
    assert draft.nodes["select"].learned_operator != original.nodes["select"].learned_operator
    with tenant_scope(tenant=ctx.tenant):
        assert store.load_flow(original.id).to_dict() == before
        assert store.load_published_bundle(original.id) is None
        events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    reviewed_events = [event for event in events if event.get("record_type") == "flow_operator_review"]
    assert [event["action"] for event in reviewed_events] == ["operator_question_requested", "operator_question_answered"]
    assert all(event["sig"] and event["record_sha256"] for event in reviewed_events)
    assert "Reviewed expected scalar result" not in json.dumps(reviewed_events)
    assert all("output" not in event and "inputs" not in event and "question" not in event for event in reviewed_events)


def test_same_request_and_answer_replay_are_stable_without_new_revision():
    ctx, service = _context(), _service()
    flow = _save_flow(ctx)
    row = _request(service, ctx, flow)
    assert _request(service, ctx, flow)["id"] == row["id"]
    answered = _answer(service, ctx, row)
    assert _answer(service, ctx, row) == answered
    assert _request(service, ctx, flow)["revision"] == answered["revision"]
    with tenant_scope(tenant=ctx.tenant):
        assert service.records.count() == 1


def test_conflicting_second_answer_cannot_replace_reviewed_evidence():
    ctx, service = _context(), _service()
    row = _request(service, ctx, _save_flow(ctx))
    accepted = _answer(service, ctx, row)
    with pytest.raises(OperatorReviewConflict, match="different reviewed answer"):
        service.answer(ctx, row["id"], not accepted["review"]["output"], expected_revision=row["revision"],
                       rationale="A different answer")
    assert service.get(ctx, row["id"])["review"] == accepted["review"]


@pytest.mark.parametrize("setting", [False, "true", 1, None])
def test_question_feature_is_strictly_opt_in(monkeypatch, setting):
    ctx, service = _context(), _service()
    flow = _save_flow(ctx)
    monkeypatch.setattr(config, "get_flows", lambda: {"learned_operator_questions": setting})
    with pytest.raises(PermissionError, match="disabled"):
        _request(service, ctx, flow)


def test_flow_master_switch_is_required(monkeypatch):
    ctx, service = _context(), _service()
    flow = _save_flow(ctx)
    monkeypatch.setenv("MAVERICK_FLOWS", "0")
    with pytest.raises(PermissionError, match="disabled"):
        _request(service, ctx, flow)


@pytest.mark.parametrize("owner", ["", "someone-else"])
def test_ownerless_and_foreign_flows_cannot_be_used_as_question_authority(owner):
    ctx, service = _context(), _service()
    flow = _save_flow(ctx, owner=owner)
    with pytest.raises(PermissionError, match="current flow owner"):
        _request(service, ctx, flow)


def test_tenant_and_resource_authority_are_not_taken_from_an_answer_body():
    ctx, service = _context(), _service()
    row = _request(service, ctx, _save_flow(ctx))
    other = _context(tenant="another-tenant")
    _save_flow(other)
    with pytest.raises(LookupError):
        service.get(other, row["id"])
    with pytest.raises(PermissionError):
        service.get(_context(resource_owner="someone-else"), row["id"])


@pytest.mark.parametrize("allowed", [False, 1, None])
def test_authorization_requires_literal_true(allowed):
    ctx, service = _context(), _service(lambda *args: allowed)
    flow = _save_flow(ctx)
    with pytest.raises(PermissionError, match="authority denied"):
        _request(service, ctx, flow)


def test_human_assertion_and_current_authorization_are_both_required():
    ctx, service = _context(), _service()
    row = _request(service, ctx, _save_flow(ctx))
    with pytest.raises(PermissionError, match="authorized human"):
        _answer(service, replace(ctx, human=False), row)
    service.authorize = lambda *args: False
    with pytest.raises(PermissionError):
        _answer(service, ctx, row)
    with tenant_scope(tenant=ctx.tenant):
        assert service.records.get(row["id"])["status"] == "awaiting_answer"


def test_exact_saved_flow_version_and_generation_are_required():
    ctx, service = _context(), _service()
    flow = _save_flow(ctx)
    with pytest.raises(OperatorReviewConflict, match="version"):
        service.request(ctx, flow.id, "select", expected_flow_version=flow.version + 1)
    with pytest.raises(OperatorReviewConflict, match="generation"):
        service.request(ctx, flow.id, "select", expected_flow_revision="old-generation")


def test_flow_edit_blocks_answer_and_export_of_previously_reviewed_draft():
    ctx, service = _context(), _service()
    flow = _save_flow(ctx)
    row = _request(service, ctx, flow)
    _answer(service, ctx, row)
    flow.name = "Changed after review"
    with tenant_scope(tenant=ctx.tenant):
        store.save_flow(flow, expected_version=flow.version, expected_revision=flow.revision)
    with pytest.raises(OperatorReviewConflict, match="source flow changed"):
        service.export_draft(ctx, row["id"])
    with pytest.raises(OperatorReviewConflict):
        _answer(service, ctx, row)


@pytest.mark.parametrize("phase", ["question", "request_commit", "refine", "answer_commit"])
def test_learning_halt_prevents_question_or_answer_commit(monkeypatch, phase):
    ctx, service = _context(), _service()
    flow = _save_flow(ctx)
    row = _request(service, ctx, flow) if phase in {"refine", "answer_commit"} else None

    def halt(job, current_phase):
        if phase == current_phase:
            raise Halted("review stopped", "test")

    monkeypatch.setattr(learning_guard, "check_learning_halt", halt)
    with pytest.raises(Halted):
        _answer(service, ctx, row) if row else _request(service, ctx, flow)
    with tenant_scope(tenant=ctx.tenant):
        if row:
            assert service.records.get(row["id"])["status"] == "awaiting_answer"
        else:
            assert service.records.count() == 0


def test_no_candidate_answer_and_stale_revision_leave_question_unchanged():
    ctx, service = _context(), _service()
    row = _request(service, ctx, _save_flow(ctx))
    with pytest.raises(ValueError):
        service.answer(ctx, row["id"], "not a boolean", expected_revision=row["revision"], rationale="Reviewed")
    with pytest.raises(OperatorReviewConflict):
        service.answer(ctx, row["id"], True, expected_revision=row["revision"] + 1, rationale="Reviewed")
    assert service.get(ctx, row["id"])["status"] == "awaiting_answer"


def test_pending_request_receipt_is_recoverable_and_does_not_expose_question(monkeypatch):
    ctx, service = _context(), _service()
    flow = _save_flow(ctx)
    real_record = audit.record
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False)
    pending = _request(service, ctx, flow)
    assert pending["status"] == "audit_pending" and pending["committed_status"] == "awaiting_answer"
    assert "question" not in pending and "base_flow" not in pending and "draft" not in pending
    assert _request(service, ctx, flow)["id"] == pending["id"]
    monkeypatch.setattr(audit, "record", real_record)
    recovered = service.get(ctx, pending["id"])
    assert recovered["status"] == "awaiting_answer" and recovered["revision"] == pending["revision"]
    assert recovered["audit_status"] == "delivered"


def test_pending_answer_receipt_withholds_draft_and_replays_without_second_transition(monkeypatch):
    ctx, service = _context(), _service()
    row = _request(service, ctx, _save_flow(ctx))
    real_record = audit.record
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False)
    pending = _answer(service, ctx, row)
    assert pending["status"] == "audit_pending" and pending["committed_status"] == "draft_ready"
    assert "refined_artifact" not in pending and "draft" not in pending
    assert _answer(service, ctx, row)["revision"] == pending["revision"]
    with pytest.raises(OperatorReviewAuditPending):
        service.export_draft(ctx, row["id"])
    monkeypatch.setattr(audit, "record", real_record)
    assert service.get(ctx, row["id"])["revision"] == pending["revision"]
    assert isinstance(service.export_draft(ctx, row["id"]), Flow)


@pytest.mark.parametrize("answered", [False, True])
@pytest.mark.parametrize("recovery_path", ["get", "answer", "export"])
def test_source_edit_does_not_strand_committed_question_or_answer_receipt(monkeypatch, answered, recovery_path):
    ctx, service = _context(), _service()
    flow = _save_flow(ctx)
    row = _request(service, ctx, flow) if answered else None
    real_record = audit.record
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False)
    pending = _answer(service, ctx, row) if answered else _request(service, ctx, flow)
    assert pending["status"] == "audit_pending"
    with tenant_scope(tenant=ctx.tenant):
        committed = service.records.get(pending["id"])
        flow.name = "Source edited after pending receipt"
        store.save_flow(flow, expected_version=flow.version, expected_revision=flow.revision)
    monkeypatch.setattr(audit, "record", real_record)
    if recovery_path == "get":
        historical = service.get(ctx, pending["id"])
        assert historical["source_current"] is False
        assert historical["audit_status"] == "delivered"
        assert "draft" not in historical and "refined_artifact" not in historical
    else:
        with pytest.raises(OperatorReviewConflict, match="source flow changed"):
            if recovery_path == "export":
                service.export_draft(ctx, pending["id"])
            else:
                _answer(service, ctx, committed)
    with tenant_scope(tenant=ctx.tenant):
        recovered = service.records.get(pending["id"])
        assert not recovered.get("_audit_pending")
        assert recovered["revision"] == committed["revision"]
        assert recovered["status"] == committed["status"]


def test_diagnostic_equivalence_cannot_be_answered_or_exported():
    ctx, service = _context(), _service()
    row = _request(service, ctx, _save_flow(ctx, ambiguous=False))
    assert row["status"] == "equivalent"
    with pytest.raises(OperatorReviewConflict):
        service.answer(ctx, row["id"], True, expected_revision=row["revision"], rationale="Reviewed")
    with pytest.raises(OperatorReviewConflict):
        service.export_draft(ctx, row["id"])


def test_capacity_is_passed_to_governed_atomic_admission(monkeypatch):
    ctx, service = _context(), _service()
    original = service.records.create
    limits = []

    def capture(record, **kwargs):
        limits.append(kwargs["max_records"])
        return original(record, **kwargs)

    monkeypatch.setattr(service.records, "create", capture)
    _request(service, ctx, _save_flow(ctx))
    assert limits == [MAX_RECORDS] == [1000]


def test_tampered_question_and_draft_are_rejected_on_read():
    ctx, service = _context(), _service()
    row = _request(service, ctx, _save_flow(ctx))
    answered = _answer(service, ctx, row)
    with tenant_scope(tenant=ctx.tenant):
        service.records.update(row["id"], lambda value: value["draft"].update(name="Unreviewed"),
                               expected_revision=answered["revision"], action="test_corruption", actor=ctx.actor)
    with pytest.raises(ValueError, match="integrity"):
        service.export_draft(ctx, row["id"])


def test_boolean_integer_alias_cannot_change_reviewed_artifact_bytes():
    ctx, service = _context(), _service()
    row = _request(service, ctx, _save_flow(ctx))
    answered = _answer(service, ctx, row)

    def change_type(value):
        value["refined_artifact"]["examples"][0]["output"] = 0

    with tenant_scope(tenant=ctx.tenant):
        service.records.update(row["id"], change_type, expected_revision=answered["revision"],
                               action="test_corruption", actor=ctx.actor)
    with pytest.raises(ValueError, match="integrity"):
        service.export_draft(ctx, row["id"])


def test_concurrent_conflicting_answers_commit_at_most_one_review():
    ctx, service = _context(), _service()
    row = _request(service, ctx, _save_flow(ctx))

    def attempt(output):
        try:
            return service.answer(ctx, row["id"], output, expected_revision=row["revision"], rationale="Reviewed")
        except RecordConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, [False, True]))
    assert sum(result is not None for result in results) == 1
    final = service.get(ctx, row["id"])
    assert final["revision"] == row["revision"] + 1 and final["status"] == "draft_ready"


def test_export_is_an_independent_copy():
    ctx, service = _context(), _service()
    row = _request(service, ctx, _save_flow(ctx))
    _answer(service, ctx, row)
    original = service.export_draft(ctx, row["id"]).to_dict()
    draft = service.export_draft(ctx, row["id"])
    draft.nodes["select"].learned_operator["artifact"]["examples"][0]["output"] = "mutated"
    assert service.export_draft(ctx, row["id"]).to_dict() == original


def test_authority_revoked_during_query_does_not_commit_a_question(monkeypatch):
    from maverick.flow import operator_queries

    ctx, service = _context(), _service()
    flow = _save_flow(ctx)
    original = operator_queries.propose_question

    def query(*args, **kwargs):
        question = original(*args, **kwargs)
        service.authorize = lambda *args: False
        return question

    monkeypatch.setattr(operator_queries, "propose_question", query)
    with pytest.raises(PermissionError):
        _request(service, ctx, flow)
    with tenant_scope(tenant=ctx.tenant):
        assert service.records.count() == 0


def test_source_flow_changed_during_query_is_rejected_before_commit(monkeypatch):
    from maverick.flow import operator_queries

    ctx, service = _context(), _service()
    flow = _save_flow(ctx)
    original = operator_queries.propose_question

    def query(*args, **kwargs):
        question = original(*args, **kwargs)
        changed = store.load_flow(flow.id)
        changed.name = "Edited while selecting the question"
        store.save_flow(changed, expected_version=flow.version, expected_revision=flow.revision)
        return question

    monkeypatch.setattr(operator_queries, "propose_question", query)
    with pytest.raises(OperatorReviewConflict):
        _request(service, ctx, flow)
    with tenant_scope(tenant=ctx.tenant):
        assert service.records.count() == 0
