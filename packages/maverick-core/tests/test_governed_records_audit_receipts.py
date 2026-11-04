"""Malformed audit acknowledgements cannot clear native durable outboxes."""
from __future__ import annotations

import copy
import hashlib

import pytest
from maverick import audit, config, crypto_at_rest, governed_records
from maverick.flow import Flow, FlowNode
from maverick.flow import store as flow_store
from maverick.flow.evolve import attach_learned_operator
from maverick.flow.learned_operator import synthesize
from maverick.flow.operator_review import OperatorReviewAuditPending, OperatorReviewService
from maverick.governed_operations import ServiceContext
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope


class _LooksTrue:
    def __bool__(self):
        return True

    def __eq__(self, other):
        return other is True


@pytest.fixture(autouse=True)
def isolated_native_state(tmp_path, monkeypatch):
    crypto_at_rest._reset_shared_key_identity_for_testing()
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    for name in ("MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_PG_DSN",
                 "MAVERICK_REPLICA_COUNT", "MAVERICK_WORLD_BACKEND"):
        monkeypatch.delenv(name, raising=False)
    key = b"g" * 32
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", "sha256:" + hashlib.sha256(key).hexdigest())
    monkeypatch.setattr(config, "get_flows", lambda: {"learned_operator_questions": True})
    yield
    crypto_at_rest._reset_shared_key_identity_for_testing()
    governed_records._reset_process_authority_pin_for_testing()


@pytest.mark.parametrize("authority_scope", ["tenant", "deployment_global"])
@pytest.mark.parametrize("receipt", [False, None, 1, 1.0, "written", {"written": True}, _LooksTrue()],
                         ids=["false", "none", "integer", "float", "text", "mapping", "equal-true-object"])
def test_only_literal_true_clears_committed_receipts_after_native_reload(
        monkeypatch, authority_scope, receipt):
    method = "record" if authority_scope == "tenant" else "record_global"
    native_record = getattr(audit, method)
    attempts = []

    def malformed(_kind, **payload):
        attempts.append(payload)
        return receipt

    monkeypatch.setattr(audit, method, malformed)
    with tenant_scope(tenant="receipt-review"):
        records = GovernedRecordStore("receipt_review", "GRA", "receipt_review",
                                      authority_scope=authority_scope)
        created = records.create({"id": "GRA-example", "status": "open", "private": "PRIVATE"},
                                 action="created", actor="reviewer")
        assert created.get("_audit_pending"), "non-True response falsely cleared the durable receipt"
        first = copy.deepcopy(created["_audit_pending"][0])
        updated = records.update(
            created["id"], lambda current: current.update(status="closed"),
            expected_revision=created["revision"], action="closed", actor="reviewer",
        )
        assert updated["revision"] == 2
        assert len(updated["_audit_pending"]) == 2
        assert updated["_audit_pending"][0] == first
        expected_receipts = copy.deepcopy(updated["_audit_pending"])

        # Reconstruct a store over the encrypted native files; this is not an
        # in-memory fake backend and is not claimed to be a process restart.
        reloaded = GovernedRecordStore("receipt_review", "GRA", "receipt_review",
                                       authority_scope=authority_scope)
        assert reloaded.get(created["id"])["_audit_pending"] == expected_receipts
        assert reloaded.retry_pending() == 0
        assert reloaded.get(created["id"])["_audit_pending"] == expected_receipts
        assert all(attempt["event_id"] == first["event_id"] for attempt in attempts)

        monkeypatch.setattr(audit, method, native_record)
        assert reloaded.retry_pending() == 1
        recovered = reloaded.get(created["id"])
        assert recovered["revision"] == 2 and recovered["status"] == "closed"
        assert "_audit_pending" not in recovered
        assert reloaded.retry_pending() == 0
        audit_log = audit.default_audit_log() if authority_scope == "tenant" else audit.global_audit_log()
        events = list(audit.iter_events(audit_dir=audit_log.audit_dir, all_days=True, strict=True, verify=True))

    events = [event for event in events if event.get("record_type") == "receipt_review"]
    assert len(events) == 2
    assert [event["event_id"] for event in events] == [item["event_id"] for item in expected_receipts]
    assert [(event["revision"], event["status"]) for event in events] == [(1, "open"), (2, "closed")]
    assert [event["record_sha256"] for event in events] == [item["record_sha256"] for item in expected_receipts]
    assert all(event["sig"] and "private" not in event for event in events)


def _service_fixture():
    ctx = ServiceContext(tenant="review-receipt", actor="user:reviewer", resource_owner="user:reviewer",
                         credential_authority="none", credential_ref="none", human=True)
    artifact = synthesize(
        {"inputs": {name: {"type": "boolean"} for name in ("x", "y")}, "output_type": "boolean"},
        [{"inputs": {"x": value, "y": value}, "output": value} for value in (False, True)],
    )
    flow = Flow(id="receipt-flow", name="Receipt flow", owner=ctx.resource_owner, start="select", nodes={
        "select": FlowNode(id="select", kind="agent", brief="Select reviewed scalar", output="answer"),
    })
    flow = attach_learned_operator(flow, "select", artifact)
    with tenant_scope(tenant=ctx.tenant):
        flow = flow_store.save_flow(flow)
    records = GovernedRecordStore("flow_operator_reviews", "LOQ", "flow_operator_review")
    service = OperatorReviewService(lambda *args: True, records=records)
    return service, ctx, flow


@pytest.mark.parametrize("stage", ["request", "answer"])
@pytest.mark.parametrize("receipt", [1, "written"])
def test_review_service_hides_unreceipted_artifacts_until_native_delivery(monkeypatch, stage, receipt):
    service, ctx, flow = _service_fixture()
    original_flow = flow.to_dict()
    native_record = audit.record
    question = None
    if stage == "answer":
        question = service.request(ctx, flow.id, "select")
        assert question["audit_status"] == "delivered"
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: receipt)
    if stage == "request":
        pending = service.request(ctx, flow.id, "select")
    else:
        pending = service.answer(ctx, question["id"], question["question"]["predictions"][0]["output"],
                                 expected_revision=question["revision"], rationale="Reviewed scalar")
    assert pending["status"] == "audit_pending"
    assert pending["audit_status"] == "pending"
    assert pending["committed_status"] == ("awaiting_answer" if stage == "request" else "draft_ready")
    hidden = {"question", "base_flow", "refined_artifact", "draft", "review", "lineage"}
    assert not hidden.intersection(pending)
    visible = service.get(ctx, pending["id"])
    assert visible["revision"] == pending["revision"]
    assert visible["status"] == "audit_pending" and not hidden.intersection(visible)
    with pytest.raises(OperatorReviewAuditPending):
        service.export_draft(ctx, pending["id"])
    with tenant_scope(tenant=ctx.tenant):
        durable = service.records.get(pending["id"])
        assert durable["_audit_pending"] and durable["status"] == pending["committed_status"]
        assert flow_store.load_flow(flow.id).to_dict() == original_flow
        assert flow_store.load_published_bundle(flow.id) is None
    monkeypatch.setattr(audit, "record", native_record)
    recovered = service.get(ctx, pending["id"])
    assert recovered["revision"] == pending["revision"] and recovered["audit_status"] == "delivered"
    if stage == "answer":
        assert service.export_draft(ctx, pending["id"]).to_dict() == recovered["draft"]
    else:
        assert recovered["status"] == "awaiting_answer" and recovered["question"]
    with tenant_scope(tenant=ctx.tenant):
        events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    events = [event for event in events if event.get("record_type") == "flow_operator_review"]
    assert len(events) == (1 if stage == "request" else 2)
    assert all(event["sig"] and not hidden.intersection(event) for event in events)
