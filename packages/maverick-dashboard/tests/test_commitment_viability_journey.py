"""Durable, bounded promise reviews through their native and Copilot controls."""
from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from maverick import config
from maverick.governed_records import GovernedRecordCapacityError
from maverick.privacy_ops import RecordConflict
from maverick_dashboard import commitment_viability_api as api
from maverick_dashboard import commitment_viability_store as reviews
from maverick_dashboard import product_operations_commitments as copilot


def _iso(value):
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _body(*, stock=1, capacity=2, option="material", second_uses_capacity=True,
          stock_certainty="confirmed"):
    now = int(time.time())
    return {"operation_id": "commitment-create-0001", "title": "Two accepted orders",
            "order_a_name": "Order Alpha", "order_a_due_at": _iso(now + 4 * 86400),
            "order_a_material_units": 1, "order_a_uses_capacity": True,
            "order_b_name": "Order Beta", "order_b_due_at": _iso(now + 5 * 86400),
            "order_b_material_units": 1, "order_b_uses_capacity": second_uses_capacity,
            "capacity_name": "Finishing line", "capacity_units": capacity,
            "material_name": "Component", "stock_units": stock,
            "stock_certainty": stock_certainty, "option_name": "Reversible supply quote",
            "option_kind": option, "option_units": 1,
            "option_ready_at": _iso(now + 3600),
            "option_expires_at": _iso(now + 86400),
            "option_lead_seconds": 0, "option_cost_note": "Price to review",
            "basis": "Operator-reported board and supplier quote, not verified by a connector.",
            "review_by": _iso(now + 2 * 86400)}


@pytest.fixture
def web(monkeypatch):
    from maverick_dashboard.app import app

    monkeypatch.setattr(config, "get_features", lambda: {"commitment_viability": True,
                                                         "copilot_operations": True})
    monkeypatch.setattr(config, "config_source_errors", lambda **_kwargs: [])
    monkeypatch.setattr(api, "require_permission", lambda *_args: None)
    monkeypatch.setattr(api, "context_for", lambda _request: "a" * 64)
    monkeypatch.setattr(api, "caller_principal", lambda _request: "user:owner")
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1",
                                    "X-Lightwork-Commitment-Context": "a" * 64})


def test_native_review_is_durable_owner_scoped_and_explicitly_unverified(web, monkeypatch):
    body = _body()
    created = web.post("/api/v1/commitment-reviews", json=body)
    assert created.status_code == 200, created.text
    identifier = created.json()["id"]
    same_request = web.post("/api/v1/commitment-reviews", json=body)
    assert same_request.json()["id"] == identifier
    report = web.get("/api/v1/commitment-reviews/" + identifier)
    assert report.status_code == 200
    data = report.json()
    assert data["assessment"]["status"] == "infeasible"
    assert len(data["resource_gaps"]) == 1
    assert data["resource_gaps"][0]["confirmed_shortfall_units"] == 1
    assert data["resource_gaps"][0]["remaining_shortfall_units"] == 0
    assert data["resource_gaps"][0]["option_ids"] == ["conditional-option"]
    assert data["resource_gap_blocked_by_order_change"] is False
    assert data["assessment"]["latest_safe_bundle_decision_at"] is not None
    assert data["source_quality"] == "operator_reported"
    assert data["external_reservation_verified"] is False
    assert data["owner_can_confirm"] is True
    assert all(row["kind"] == "operator_assertion" for row in data["sources"])
    assert web.get("/api/v1/commitment-reviews").json()["items"][0]["id"] == identifier

    # Model owner records intent. Neither this decision nor an idempotent retry
    # claims a supplier order or changes the accepted customer orders.
    decision = {"expected_revision": data["revision"], "operation_id": "confirm-choice-0001",
                "kind": "option", "proposal_id": "", "option_id": "conditional-option"}
    first = web.post(f"/api/v1/commitment-reviews/{identifier}/confirm", json=decision)
    assert first.status_code == 200, first.text
    assert web.post(f"/api/v1/commitment-reviews/{identifier}/confirm", json=decision).json() == first.json()
    after = web.get("/api/v1/commitment-reviews/" + identifier).json()
    assert after["model"]["options"][0]["owner_confirmation"] is not None
    assert after["external_reservation_verified"] is False
    assert after["revision"] == first.json()["revision"]
    assert web.post(f"/api/v1/commitment-reviews/{identifier}/confirm",
                    json={**decision, "operation_id": "stale-decision-0001"}).status_code == 409

    monkeypatch.setattr(api, "caller_principal", lambda _request: "user:other")
    assert web.get("/api/v1/commitment-reviews/" + identifier).json()["owner_can_confirm"] is False
    assert web.post(f"/api/v1/commitment-reviews/{identifier}/confirm",
                    json=decision).status_code == 403
    assert web.post("/api/v1/commitment-reviews", json=body).status_code == 403
    assert web.post(f"/api/v1/commitment-reviews/{identifier}/confirm",
                    json={**decision, "expected_revision": after["revision"],
                          "operation_id": "other-decision-0001"}).status_code == 403
    monkeypatch.setattr(api, "context_for", lambda _request: "b" * 64)
    assert web.get("/api/v1/commitment-reviews/" + identifier).status_code == 409


def test_owner_archives_full_review_and_frees_active_capacity(web, monkeypatch):
    monkeypatch.setattr(reviews, "LIMIT", 1)
    created = web.post("/api/v1/commitment-reviews", json=_body())
    assert created.status_code == 200, created.text
    identifier = created.json()["id"]
    before = web.get(f"/api/v1/commitment-reviews/{identifier}").json()
    other = {**_body(), "operation_id": "second-commitment-create-0001"}
    assert web.post("/api/v1/commitment-reviews", json=other).status_code == 409
    archive_body = {"expected_revision": before["revision"],
                    "operation_id": "archive-review-0001", "confirm_finished": True}
    assert web.post(f"/api/v1/commitment-reviews/{identifier}/archive",
                    json={**archive_body, "confirm_finished": False}).status_code == 422
    monkeypatch.setattr(api, "caller_principal", lambda _request: "user:other")
    assert web.post(f"/api/v1/commitment-reviews/{identifier}/archive",
                    json=archive_body).status_code == 403
    monkeypatch.setattr(api, "caller_principal", lambda _request: "user:owner")
    archived = web.post(f"/api/v1/commitment-reviews/{identifier}/archive", json=archive_body)
    assert archived.status_code == 200, archived.text
    assert archived.json()["archived"] is True
    assert reviews.STORE.get(identifier) is None
    saved = reviews.archived_get(identifier, "a" * 64)
    assert saved["source"]["sources"] == before["sources"]
    assert saved["source"]["model"] == before["model"]
    assert web.get("/api/v1/commitment-reviews").json()["items"] == []
    archived_rows = web.get("/api/v1/commitment-reviews?archived=true").json()["items"]
    assert archived_rows[0]["id"] == identifier
    historical = web.get(f"/api/v1/commitment-reviews/{identifier}").json()
    assert historical["archived"] is True and historical["owner_can_confirm"] is False
    assert historical["sources"] == before["sources"]
    assert web.post(f"/api/v1/commitment-reviews/{identifier}/archive",
                    json=archive_body).status_code == 200
    assert web.post("/api/v1/commitment-reviews", json=_body()).status_code == 409
    assert web.post("/api/v1/commitment-reviews", json=other).status_code == 200
    monkeypatch.setattr(api, "context_for", lambda _request: "b" * 64)
    hidden = web.get(f"/api/v1/commitment-reviews/{identifier}",
                     headers={"X-Lightwork-Commitment-Context": "b" * 64})
    assert hidden.status_code == 404


def test_archive_waits_for_receipts_and_can_resume_after_reload(web, monkeypatch):
    from maverick import audit

    row = web.post("/api/v1/commitment-reviews", json=_body()).json()
    body = {"expected_revision": row["revision"],
            "operation_id": "archive-with-pending-receipt-0001", "confirm_finished": True}
    deliver = audit.record
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
    pending = web.post(f"/api/v1/commitment-reviews/{row['id']}/archive", json=body)
    assert pending.status_code == 503
    assert reviews.STORE.get(row["id"]) is not None
    assert reviews.ARCHIVE.get(reviews._archive_id(row["id"])) is None
    latest = web.get(f"/api/v1/commitment-reviews/{row['id']}").json()
    assert latest["archive_pending"] is True
    assert latest["owner_can_confirm"] is False
    monkeypatch.setattr(audit, "record", deliver)
    # The browser can reload and resume with the current revision and a new
    # operation reference; it never needs terminal access to recover.
    resumed = web.post(f"/api/v1/commitment-reviews/{row['id']}/archive",
                       json={**body, "expected_revision": latest["revision"],
                             "operation_id": "archive-after-browser-reload-0001"})
    assert resumed.status_code == 200, resumed.text
    assert reviews.STORE.get(row["id"]) is None
    assert web.get(f"/api/v1/commitment-reviews/{row['id']}").json()["archived"] is True


def test_copilot_can_archive_and_read_retained_review(web, monkeypatch):
    row = web.post("/api/v1/commitment-reviews", json=_body()).json()
    monkeypatch.setattr(api, "_context", lambda _request, mutation=False: "a" * 64)
    monkeypatch.setattr(api, "_actor", lambda _request: "user:owner")
    selection = {"kind": "commitment_review", "id": row["id"]}
    assert "commitments.archive_review" in {item.id for item in copilot.entries()}
    prepared = copilot.archive_prepare(object(), selection, {})
    assert prepared.native["expected_revision"] == row["revision"]
    outcome = copilot.archive_execute(object(), selection, {}, prepared.native,
                                      "copilot-archive-review-0001")
    assert outcome.status == "confirmed" and outcome.details["archived"] is True
    assert copilot.archive_recover(object(), selection, {}, prepared.native,
                                   "copilot-archive-review-0001").status == "replayed"
    assessment = copilot.assessment_snapshot(object(), selection)
    assert assessment.details["archived"] is True
    assert assessment.details["resource_gaps"][0]["confirmed_shortfall_units"] == 1
    assert assessment.details["resource_gap_blocked_by_order_change"] is False


def test_reported_trace_requires_owner_review_and_recomputes_both_orders(monkeypatch):
    body = api.NewReviewIn(**_body(stock=2, capacity=1, option="capacity",
                                   second_uses_capacity=False)).service_body()
    row = reviews.create("c" * 64, "user:owner", body)
    before = reviews.project(row)
    assert before["assessment"]["status"] == "feasible"
    now = int(time.time())
    trace = {"expected_revision": row["revision"], "operation_id": "trace-observation-0001",
             "running_order": "order-a", "blocked_order": "order-b",
             "started_at": now - 300, "ended_at": now - 120, "observed_at": now - 60,
             "review_by": now + 86400,
             "basis": "Operator shift log reports overlap at the finishing line."}
    traced = reviews.record_trace(row["id"], "c" * 64, "user:observer", trace)
    suggestion = reviews.project(traced)["proposals"]
    assert len(suggestion) == 1
    assert suggestion[0]["left_id"] == "order-a"
    decision = {"expected_revision": traced["revision"], "operation_id": "confirm-edge-0001",
                "kind": "dependency", "proposal_id": suggestion[0]["id"],
                "option_id": "conditional-option"}
    with pytest.raises(PermissionError):
        reviews.confirm(row["id"], "c" * 64, "user:observer", decision)
    confirmed = reviews.confirm(row["id"], "c" * 64, "user:owner", decision)
    current = reviews.project(confirmed)
    assert current["assessment"]["status"] == "infeasible"
    assert current["assessment"]["recomputed_commitment_ids"] == ("order-a", "order-b")
    assert current["proposals"] == []
    assert current["model"]["dependencies"][0]["confirmed_by"] != "user:owner"
    assert current["external_reservation_verified"] is False
    with pytest.raises(RecordConflict):
        reviews.record_trace(row["id"], "c" * 64, "user:owner",
                             {**trace, "operation_id": "stale-trace-0001"})
    monkeypatch.setattr(reviews.time, "time", lambda: now + 3 * 86400)
    stale = reviews.project(reviews.get(row["id"], "c" * 64))
    assert stale["assessment"]["stale_source_ids"]
    assert stale["assessment"]["status"] != "feasible"


def test_saved_review_and_observation_retries_survive_expired_windows(monkeypatch):
    context = "g" * 64
    body = api.NewReviewIn(**_body()).service_body()
    created = reviews.create(context, "user:owner", body)
    now = int(time.time())
    trace = {"expected_revision": created["revision"],
             "operation_id": "retry-observation-0001",
             "running_order": "order-a", "blocked_order": "order-b",
             "started_at": now - 300, "ended_at": now - 120,
             "observed_at": now - 60, "review_by": now + 3600,
             "basis": "Shift observation recorded before the review window closed."}
    saved = reviews.record_trace(created["id"], context, "user:owner", trace)
    clock = {"now": body["review_by"] + 1}
    monkeypatch.setattr(reviews.time, "time", lambda: clock["now"])

    assert reviews.create(context, "user:owner", body)["id"] == created["id"]
    assert reviews.record_trace(created["id"], context, "user:owner", trace)["revision"] == saved["revision"]
    with pytest.raises(RecordConflict, match="different work"):
        reviews.create(context, "user:owner", {**body, "title": "Changed"})
    with pytest.raises(RecordConflict, match="different work"):
        reviews.record_trace(created["id"], context, "user:owner",
                             {**trace, "basis": "Changed observation"})
    with pytest.raises(ValueError, match="review time"):
        reviews.record_trace(created["id"], context, "user:owner",
                             {**trace, "operation_id": "new-observation-0001"})


def test_copilot_uses_selected_review_and_same_owner_authority(web, monkeypatch):
    row = web.post("/api/v1/commitment-reviews", json=_body()).json()
    from maverick_dashboard.product_operations import adapters

    assert "commitments.confirm_choice" in adapters()
    request = type("Request", (), {})()
    monkeypatch.setattr(api, "_context", lambda _request, mutation=False: "a" * 64)
    selection = {"kind": "commitment_review", "id": row["id"]}
    status = copilot.assessment_snapshot(request, selection)
    assert status.details["source_quality"] == "operator_reported"
    state = copilot.choice_snapshot(request, selection)
    assert not state.blocked
    preview = copilot.choice_prepare(request, selection, {})
    assert preview.native["expected_revision"] == row["revision"]
    outcome = copilot.choice_execute(request, selection, {}, preview.native, "copilot-choice-0001")
    assert outcome.status == "confirmed"
    assert copilot.choice_recover(request, selection, {}, preview.native,
                                  "copilot-choice-0001").status == "replayed"
    monkeypatch.setattr(api, "_actor", lambda _request: "user:other")
    with pytest.raises(Exception) as exc:
        copilot.choice_snapshot(request, selection)
    assert getattr(exc.value, "status_code", None) == 403


def test_copilot_create_uses_local_datetime_fields_and_hours(monkeypatch):
    monkeypatch.setattr(api, "_context", lambda _request, mutation=False: "d" * 64)
    monkeypatch.setattr(api, "_actor", lambda _request: "user:owner")
    state = copilot.create_snapshot(object(), {})
    fields = {item["name"]: item for item in state.fields}
    assert fields["order_a_due_at"]["kind"] == "datetime-local"
    assert fields["review_by"]["kind"] == "datetime-local"
    assert fields["option_lead_hours"]["label"] == "Lead time in hours after a decision"
    assert fields["option_cost_note"]["required"] is False
    assert "option_lead_seconds" not in fields
    body = _body()
    body.pop("operation_id")
    body.pop("option_lead_seconds")
    body.pop("option_cost_note")
    body["option_lead_hours"] = 2
    preview = copilot.create_prepare(object(), {}, body)
    outcome = copilot.create_execute(object(), {}, body, preview.native, "copilot-create-0001")
    assert outcome.status == "confirmed"
    saved = reviews.get(outcome.details["id"], "d" * 64)
    assert saved["model"]["options"][0]["lead_seconds"] == 7200


def test_uncertain_conditional_path_is_not_offered_for_owner_confirmation(monkeypatch):
    body = api.NewReviewIn(**_body(stock_certainty="unknown")).service_body()
    row = reviews.create("e" * 64, "user:owner", body)
    monkeypatch.setattr(api, "_context", lambda _request, mutation=False: "e" * 64)
    monkeypatch.setattr(api, "_actor", lambda _request: "user:owner")
    state = copilot.choice_snapshot(object(), {"kind": "commitment_review", "id": row["id"]})
    assert state.blocked
    assert "No current actionable path" in state.blocked


def test_time_is_rechecked_inside_locked_owner_decision_and_observation(monkeypatch):
    row = reviews.create("f" * 64, "user:owner",
                         api.NewReviewIn(**_body()).service_body())
    initial = reviews.project(row)
    expires = initial["model"]["options"][0]["expires_at"]
    clock = {"now": time.time()}
    monkeypatch.setattr(reviews.time, "time", lambda: clock["now"])
    real_update = reviews.STORE.update

    def delayed_update(*args, **kwargs):
        clock["now"] = expires + 1
        return real_update(*args, **kwargs)

    monkeypatch.setattr(reviews.STORE, "update", delayed_update)
    decision = {"expected_revision": row["revision"], "operation_id": "late-choice-0001",
                "kind": "option", "proposal_id": "", "option_id": "conditional-option"}
    with pytest.raises(ValueError, match="unavailable"):
        reviews.confirm(row["id"], "f" * 64, "user:owner", decision)
    after = reviews.get(row["id"], "f" * 64)
    assert after["revision"] == row["revision"]
    assert after["model"]["options"][0]["owner_confirmation"] is None

    clock["now"] = expires - 10
    trace = {"expected_revision": row["revision"], "operation_id": "late-trace-0001",
             "running_order": "order-a", "blocked_order": "order-b",
             "started_at": expires - 300, "ended_at": expires - 200,
             "observed_at": expires - 100, "review_by": expires + 0.5,
             "basis": "Operator shift log reports overlap at the finishing line."}
    with pytest.raises(RecordConflict, match="expired while saving"):
        reviews.record_trace(row["id"], "f" * 64, "user:owner", trace)
    assert reviews.get(row["id"], "f" * 64)["traces"] == []


def test_delayed_admission_or_workspace_capacity_never_reports_new_review_as_actionable(web, monkeypatch):
    body = _body()
    real_create = reviews.STORE.create
    original_now = time.time()
    clock = {"now": original_now}
    monkeypatch.setattr(reviews.time, "time", lambda: clock["now"])

    def delayed_create(*args, **kwargs):
        saved = real_create(*args, **kwargs)
        clock["now"] = api._when(body["option_expires_at"]) + 1
        return saved

    monkeypatch.setattr(reviews.STORE, "create", delayed_create)
    response = web.post("/api/v1/commitment-reviews", json=body)
    assert response.status_code == 409
    assert "Check saved reviews" in response.text
    saved = web.get("/api/v1/commitment-reviews").json()["items"]
    assert len(saved) == 1
    report = web.get("/api/v1/commitment-reviews/" + saved[0]["id"]).json()
    assert report["assessment"]["status"] != "feasible"

    def full(*args, **kwargs):
        raise GovernedRecordCapacityError("full")

    monkeypatch.setattr(reviews.STORE, "create", full)
    clock["now"] = original_now
    next_body = {**body, "operation_id": "another-new-review-0001"}
    full_response = web.post("/api/v1/commitment-reviews", json=next_body)
    assert full_response.status_code == 409
    assert "1,000-active-review pilot limit across its workspaces" in full_response.text
    assert "Finish and archive a completed review" in full_response.text


def test_native_review_waits_for_audit_receipts_and_exact_retries_recover(web, monkeypatch):
    from maverick import audit

    body = _body()
    deliver = audit.record
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
    pending_create = web.post("/api/v1/commitment-reviews", json=body)
    assert pending_create.status_code == 503
    assert pending_create.json()["status"] == "audit_pending"
    identifier = pending_create.json()["id"]
    assert web.get(f"/api/v1/commitment-reviews/{identifier}").json()["audit_status"] == "pending"
    assert web.post("/api/v1/commitment-reviews", json=body).status_code == 503
    monkeypatch.setattr(audit, "record", deliver)
    created = web.post("/api/v1/commitment-reviews", json=body)
    assert created.status_code == 200 and created.json()["id"] == identifier
    assert web.get(f"/api/v1/commitment-reviews/{identifier}").json()["audit_status"] == "recorded"

    now = int(time.time())
    observation = {"expected_revision": created.json()["revision"],
                   "operation_id": "audit-trace-observation-0001",
                   "running_order": "order-a", "blocked_order": "order-b",
                   "started_at": _iso(now - 300), "ended_at": _iso(now - 120),
                   "observed_at": _iso(now - 60), "review_by": _iso(now + 3600),
                   "basis": "A named operator observed the line and its waiting order."}
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
    pending_trace = web.post(f"/api/v1/commitment-reviews/{identifier}/observations", json=observation)
    assert pending_trace.status_code == 503
    trace_revision = pending_trace.json()["revision"]
    assert web.post(f"/api/v1/commitment-reviews/{identifier}/observations", json=observation).status_code == 503
    blocked = {"expected_revision": trace_revision, "operation_id": "audit-choice-blocked-0001",
               "kind": "option", "proposal_id": "", "option_id": "conditional-option"}
    assert web.post(f"/api/v1/commitment-reviews/{identifier}/confirm", json=blocked).status_code == 503
    monkeypatch.setattr(audit, "record", deliver)
    recovered = web.post(f"/api/v1/commitment-reviews/{identifier}/observations", json=observation)
    assert recovered.status_code == 200 and recovered.json()["revision"] == trace_revision

    decision = {**blocked, "operation_id": "audit-choice-confirm-0001"}
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
    pending_choice = web.post(f"/api/v1/commitment-reviews/{identifier}/confirm", json=decision)
    assert pending_choice.status_code == 503
    assert pending_choice.json()["status"] == "audit_pending"
    assert web.post(f"/api/v1/commitment-reviews/{identifier}/confirm", json=decision).status_code == 503
    monkeypatch.setattr(audit, "record", deliver)
    confirmed = web.post(f"/api/v1/commitment-reviews/{identifier}/confirm", json=decision)
    assert confirmed.status_code == 200 and confirmed.json()["revision"] == pending_choice.json()["revision"]
    assert web.get(f"/api/v1/commitment-reviews/{identifier}").json()["audit_status"] == "recorded"


def test_copilot_decision_stays_unconfirmed_until_audit_receipt_recovers(web, monkeypatch):
    from maverick import audit

    row = web.post("/api/v1/commitment-reviews", json=_body()).json()
    request = object()
    monkeypatch.setattr(api, "_context", lambda _request, mutation=False: "a" * 64)
    selection = {"kind": "commitment_review", "id": row["id"]}
    prepared = copilot.choice_prepare(request, selection, {}).native
    deliver = audit.record
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
    outcome = copilot.choice_execute(request, selection, {}, prepared, "audit-copilot-choice-0001")
    assert outcome.status == "unconfirmed"
    assert copilot.choice_recover(request, selection, {}, prepared,
                                  "audit-copilot-choice-0001").status == "unconfirmed"
    assert "activity receipt" in copilot.choice_snapshot(request, selection).blocked
    monkeypatch.setattr(audit, "record", deliver)
    assert copilot.choice_recover(request, selection, {}, prepared,
                                  "audit-copilot-choice-0001").status == "replayed"


def test_committed_write_with_lost_response_stays_unconfirmed_until_receipt(web, monkeypatch):
    from maverick import audit

    row = web.post("/api/v1/commitment-reviews", json=_body()).json()
    body = {"expected_revision": row["revision"], "operation_id": "audit-lost-response-0001",
            "kind": "option", "proposal_id": "", "option_id": "conditional-option"}
    deliver = audit.record
    update = reviews.STORE.update
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)

    def lose_after_commit(*args, **kwargs):
        update(*args, **kwargs)
        raise OSError("response lost after commit")

    monkeypatch.setattr(reviews.STORE, "update", lose_after_commit)
    pending = web.post(f"/api/v1/commitment-reviews/{row['id']}/confirm", json=body)
    assert pending.status_code == 503
    assert pending.json()["status"] == "audit_pending"
    monkeypatch.setattr(reviews.STORE, "update", update)
    monkeypatch.setattr(audit, "record", deliver)
    recovered = web.post(f"/api/v1/commitment-reviews/{row['id']}/confirm", json=body)
    assert recovered.status_code == 200
    assert recovered.json()["revision"] == pending.json()["revision"]


def test_a_non_ascii_context_header_is_refused_like_any_other_wrong_one(web):
    # Header text arrives decoded as latin-1, so e-acute is a non-ASCII str.
    for value in ("b" * 64, b"caf\xe9"):
        refused = web.get("/api/v1/commitment-reviews", headers={"X-Lightwork-Commitment-Context": value})
        assert refused.status_code == 409, (value, refused.status_code, refused.text)


def test_owner_checks_compare_non_ascii_account_names_instead_of_failing():
    """A signed-in subject may be any printable text. The owner is admitted and
    another account refused, whatever characters either name holds."""
    context = "n" * 64
    owner, other = "user:josé", "user:zoë"
    body = api.NewReviewIn(**_body()).service_body()
    created = reviews.create(context, owner, body)
    assert reviews.create(context, owner, body)["id"] == created["id"]
    with pytest.raises(PermissionError):
        reviews.create(context, other, body)
    decision = {"expected_revision": created["revision"], "operation_id": "confirm-choice-non-ascii",
                "kind": "option", "proposal_id": "", "option_id": "conditional-option"}
    with pytest.raises(PermissionError):
        reviews.confirm(created["id"], context, other, decision)
    confirmed = reviews.confirm(created["id"], context, owner, decision)
    assert confirmed["revision"] > created["revision"]
    archive = {"expected_revision": confirmed["revision"], "operation_id": "archive-non-ascii-0001",
               "confirm_finished": True}
    with pytest.raises(PermissionError):
        reviews.retire(created["id"], context, other, archive)
    assert reviews.retire(created["id"], context, owner, archive)["retired_by"] == owner
    with pytest.raises(RecordConflict):
        reviews.retire(created["id"], context, other, archive)
