"""Reviewed learning with real PostgreSQL CAS, RLS and durable receipt recovery."""
from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import audit, config, governed_records
from maverick.flow import Flow, FlowNode, store
from maverick.flow.evolve import attach_learned_operator
from maverick.flow.learned_operator import synthesize
from maverick.flow.operator_review import (
    OperatorReviewAuditPending,
    OperatorReviewService,
)
from maverick.governed_operations import ServiceContext
from maverick.governed_records import (
    GovernedRecordStore,
    PostgresGovernedRecordBackend,
    RecordConflict,
)
from maverick.paths import tenant_scope

from test_support.postgres_authority import authority as authority

pytestmark = pytest.mark.skipif(not os.environ.get("MAVERICK_PG_DSN"),
                                reason="dedicated Postgres service unavailable")


@pytest.fixture
def reviews(authority, monkeypatch):
    factory, _, _ = authority
    # The owned fixture provisions a real NOSUPERUSER/NOBYPASSRLS role.
    # Independent unpooled adapters exercise PostgreSQL's transaction boundary.
    dsn = factory()._dsn
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", dsn)
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    # Strict verification requires signed receipts in the ordinary posture too.
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setattr(config, "get_flows", lambda: {"learned_operator_questions": True})

    def service():
        backend = PostgresGovernedRecordBackend("flow_operator_reviews", "LOQ", dsn=dsn,
                                                require_bound_tenant=True)
        records = GovernedRecordStore("flow_operator_reviews", "LOQ", "flow_operator_review",
                                      backend=backend, required_backend="postgres")
        return OperatorReviewService(lambda *args: True, records=records)

    yield service
    governed_records._reset_process_authority_pin_for_testing()


def _ctx(tenant="alpha"):
    return ServiceContext(tenant=tenant, actor="reviewer:alice", resource_owner="reviewer:alice",
                          credential_authority="none", credential_ref="none", human=True)


def _flow(ctx, *, composed=False):
    spec = {"inputs": {key: {"type": "boolean"} for key in ("x", "y")}, "output_type": "boolean"}
    examples = [{"inputs": {"x": value, "y": value}, "output": value} for value in (False, True)]
    if composed:
        from maverick.flow.composed_operator import synthesize as compose

        artifact = compose(spec, examples, max_operations=2, operators=["if", "not"])
    else:
        artifact = synthesize(spec, examples)
    flow = Flow(id="native-review", name="Native review", owner=ctx.resource_owner, start="select",
                nodes={"select": FlowNode(id="select", kind="agent", brief="Select the result", output="result")})
    with tenant_scope(tenant=ctx.tenant):
        return store.save_flow(attach_learned_operator(flow, "select", artifact))


@pytest.mark.parametrize("receipt", [False, 1])
@pytest.mark.parametrize("composed", [False, True])
def test_native_pending_answer_recovers_across_adapters_without_replaying_transition(reviews, monkeypatch, receipt, composed):
    ctx, service = _ctx(), reviews()
    original = _flow(ctx, composed=composed)
    question = service.request(ctx, original.id, "select")
    record = audit.record
    monkeypatch.setattr(audit, "record", lambda *a, **kw: receipt)
    answered = service.answer(ctx, question["id"], True, expected_revision=question["revision"],
                              rationale="Reviewed against business rule")
    assert answered["status"] == "audit_pending" and answered["committed_status"] == "draft_ready"
    assert "draft" not in answered and "refined_artifact" not in answered
    with pytest.raises(OperatorReviewAuditPending):
        reviews().export_draft(ctx, question["id"])
    monkeypatch.setattr(audit, "record", record)
    recovered = reviews().get(ctx, question["id"])
    assert recovered["revision"] == answered["revision"]
    assert recovered["review"]["output"] is True
    assert recovered["audit_status"] == "delivered"
    assert reviews().export_draft(ctx, question["id"]).to_dict() == recovered["draft"]
    with tenant_scope(tenant="alpha"):
        assert store.load_flow(original.id).to_dict() == original.to_dict()
        assert store.load_published_bundle(original.id) is None
        events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
                  if event.get("record_type") == "flow_operator_review"]
        assert [event["action"] for event in events] == ["operator_question_requested", "operator_question_answered"]
        assert all(event["sig"] for event in events)
    with tenant_scope(tenant="beta"):
        assert reviews().records.get(question["id"]) is None


@pytest.mark.parametrize("composed", [False, True])
def test_native_conflicting_answers_commit_one_complete_lineage(reviews, composed):
    ctx, service = _ctx(), reviews()
    original = _flow(ctx, composed=composed)
    question = service.request(ctx, original.id, "select")
    barrier = threading.Barrier(2)

    def answer(output):
        independent = reviews()
        barrier.wait(timeout=10)
        try:
            return independent.answer(ctx, question["id"], output, expected_revision=question["revision"],
                                      rationale="Independent reviewed answer")
        except RecordConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(answer, (False, True)))
    winners = [row for row in results if row is not None]
    assert len(winners) == 1
    persisted = reviews().get(ctx, question["id"])
    assert persisted["revision"] == question["revision"] + 1
    assert persisted["review"] == winners[0]["review"]
    assert persisted["lineage"] == winners[0]["lineage"]
    assert reviews().export_draft(ctx, question["id"]).to_dict() == persisted["draft"]
    with tenant_scope(tenant=ctx.tenant):
        assert store.load_flow(original.id).to_dict() == original.to_dict()
        assert service.records.count() == 1
