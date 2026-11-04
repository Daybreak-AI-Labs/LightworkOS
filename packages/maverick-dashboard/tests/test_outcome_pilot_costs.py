"""Synthetic admitted billing receipts, not live invoice acceptance."""
from __future__ import annotations

import copy
import hashlib
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import ai_cost_roi as billing
from maverick import audit, config
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict
from maverick_dashboard import outcome_accounting_bridge as accounting_bridge
from maverick_dashboard import outcome_pilot_costs as costs
from maverick_dashboard import outcome_pilot_costs_api as api
from maverick_dashboard import outcome_pilots as pilots
from maverick_dashboard import outcome_pilots_api as pilot_api
from maverick_dashboard import rbac

START, END = "2026-08-01T00:00:00Z", "2026-09-01T00:00:00Z"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    for name in ("MAVERICK_TENANT", "MAVERICK_DASHBOARD_ADMINS", "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(audit, "record", lambda *a, **k: True)
    monkeypatch.setattr(audit, "record_global", lambda *a, **k: True)
    monkeypatch.setattr(config, "get_features", lambda: {"outcome_measurement": True})
    monkeypatch.setattr(config, "config_source_errors", lambda **k: [])
    monkeypatch.setattr(billing, "enabled", lambda: True)
    config.reset_config_cache()
    with tenant_scope(tenant="cost-workspace"):
        yield
    config.reset_config_cache()


def citation(label):
    return billing.SourceCitation(uri="s3://synthetic-costs/" + label, sha256=hashlib.sha256(label.encode()).hexdigest(), row_ref=label)


def ingest(identifier="original", amount="10.000000001", currency="USD", corrects=""):
    record = billing.NormalizedBillingRecord(provider=billing.BillingProvider.OPENAI,
        source_account_id="synthetic-account", source_record_id=identifier, period_start=START, period_end=END,
        currency=currency, cost=amount, usage=(billing.UsageQuantity("tokens", "1", "tokens"),),
        service="synthetic-service", resource_id="synthetic-model", citation=citation(identifier),
        correction_of_source_record_id=corrects, correction_reason="Synthetic billing adjustment" if corrects else "")
    batch = billing.BillingCollection(provider=record.provider, collector_id="synthetic_fixture",
        source_account_id=record.source_account_id, batch_id=identifier, period_start=START, period_end=END,
        collected_at=1800000000., manifest_citation=citation("manifest-" + identifier), records=(record,))
    return billing.default_service.ingest(batch, actor="user:alice")


@pytest.fixture
def planned():
    records = {str(i): {"unstarted": True, "input_version": "input-" + str(i), "version": "a" * 64,
        "sample": False, "finished": False, "accepted": False} for i in range(1, 5)}
    def resolve(kind, reference):
        return records[reference]
    record = pilots.create({"title": "Cost pilot", "customer": "Synthetic", "workflow": "Review",
        "criteria": "Reviewed result", "operation_id": "synthetic-cost-plan",
        "cases": [{"kind": "goal", "reference": str(i), "label": "Case " + str(i)} for i in range(1, 5)]},
        context="alice", actor="user:alice", resolve=resolve)
    manifest = accounting_bridge.admit_pilot(record, resolve=resolve)
    record = pilots.complete_admission(
        record["id"], manifest, context="alice", actor="user:alice", resolve=resolve,
    )
    return record, records, resolve


def body(record, **changes):
    source = next(iter(costs.sources().values()))
    value = {"expected_revision": record["revision"], "operation_id": "synthetic-cost-allocation",
             "observation_id": source["id"], "billing_version": source["version"],
             "shares": [{"case_id": "1", "basis_points": 2500, "source_version": "a" * 64},
                        {"case_id": "2", "basis_points": 7500, "source_version": "a" * 64}],
             "note": "Synthetic fixture attribution; no provider verification.", "confirm": True}
    return api.AllocationIn(**{**value, **changes}).model_dump()


def save(record, resolve, value=None):
    return costs.allocate(record["id"], value or body(record), context="alice", actor="user:alice", resolve=resolve)


def test_exact_amounts_currency_and_reported_costs_stay_separate(planned):
    record, _, resolve = planned
    ingest()
    saved = save(record, resolve)
    report = costs.report(saved, resolve=resolve)
    assert report["current_totals_by_currency"] == {"USD": "10.000000001"}
    assert report["current_case_totals"] == {"1": {"USD": "2.50000000025"}, "2": {"USD": "7.50000000075"}}
    assert report["provider_invoice_verified"] is False
    assert report["allocations"][0]["source"]["receipts"][0]["collector_id"] == "synthetic_fixture"
    assert all(case["measurement"] is None for case in saved["cases"])
    assert saved["operations"] == record["operations"]
    assert saved["creation_request"] == record["creation_request"]
    assert save(saved, resolve, body(record))["revision"] == saved["revision"]
    with pytest.raises(RecordConflict):
        save(saved, resolve, body(saved, note="Different attribution under same reference"))


def test_operator_human_and_rework_costs_stay_distinct_from_provider_allocations(planned):
    record, _, resolve = planned
    ingest()
    saved = save(record, resolve)
    fields = {"expected_revision": saved["revision"], "operation_id": "record-human-cost-evidence",
              "source_version": "a" * 64, "human_cost": "25.50", "rework_cost": "4.25",
              "evidence": "Synthetic timing and rate sheet", "note": "Operator reported, including review"}
    with pytest.raises(ValueError, match="Currency"):
        pilot_api.ObservationIn(**fields)
    value = pilot_api.ObservationIn(**fields, currency="USD").model_dump()
    updated = pilots.observe(saved["id"], "1", value, context="alice", actor="user:alice", resolve=resolve)
    measurement = updated["cases"][0]["measurement"]
    assert measurement["human_cost"] == "25.50" and measurement["rework_cost"] == "4.25"
    assert measurement["ai_total_cost"] is None
    assert costs.report(updated, resolve=resolve)["current_totals_by_currency"] == {"USD": "10.000000001"}


def full_costs(planned, amount="40"):
    record, records, resolve = planned
    ingest(amount=amount)
    admissions = {
        row["case_id"]: row["admitted_at"]
        for row in record["admission_manifest"]["entries"]
    }
    for case_id, row in records.items():
        row.update(
            finished=True,
            unstarted=False,
            first_started_at=admissions[case_id] + 1,
        )
    records["1"]["accepted"] = True
    saved = save(record, resolve, body(record, shares=[{"case_id": str(i), "basis_points": 2500,
        "source_version": "a" * 64} for i in range(1, 5)]))
    return saved, records, resolve


def coverage_body(record, resolve, **changes):
    current = costs.report(record, resolve=resolve)["coverage"]
    return api.CoverageIn(expected_revision=record["revision"], operation_id="confirm-all-planned-case-costs",
        coverage_version=current["version"], currency=current["currency"] or "USD",
        note="Reviewed all cases, failed attempts and rejections; synthetic evidence only.", confirm=True,
        **changes).model_dump()


def confirm_costs(record, resolve, value=None):
    return costs.confirm_coverage(record["id"], value or coverage_body(record, resolve), context="alice",
                                  actor="user:alice", resolve=resolve)


def test_per_accepted_cost_requires_review_and_includes_all_rejected_case_costs(planned):
    record, _, resolve = full_costs(planned)
    coverage = costs.report(record, resolve=resolve)["coverage"]
    assert coverage["can_confirm"] and coverage["status"] == "needs_review"
    assert coverage["provider_cost_per_accepted_outcome"] is None
    saved = confirm_costs(record, resolve)
    coverage = costs.report(saved, resolve=resolve)["coverage"]
    assert coverage["status"] == "complete"
    assert coverage["provider_cost_per_accepted_outcome"]["amount"] == "40"
    assert coverage["provider_cost_per_accepted_outcome"]["accepted_outcomes"] == 1
    assert coverage["provider_cost_per_accepted_outcome"]["planned_cases"] == 4
    assert confirm_costs(saved, resolve, coverage_body(record, resolve))["revision"] == saved["revision"]


def test_missing_case_cost_never_becomes_zero_or_complete_coverage(planned):
    record, records, resolve = planned
    ingest()
    admissions = {
        row["case_id"]: row["admitted_at"]
        for row in record["admission_manifest"]["entries"]
    }
    for case_id, row in records.items():
        row.update(
            finished=True,
            unstarted=False,
            first_started_at=admissions[case_id] + 1,
        )
    records["1"]["accepted"] = True
    saved = save(record, resolve)
    coverage = costs.report(saved, resolve=resolve)["coverage"]
    assert coverage["missing_or_ineligible_cases"] == ["3", "4"]
    assert coverage["provider_cost_per_accepted_outcome"] is None
    with pytest.raises(ValueError, match="Every planned case"):
        confirm_costs(saved, resolve)


def test_pre_admission_start_cannot_be_confirmed_as_complete_cost_coverage(planned):
    record, records, resolve = full_costs(planned)
    admitted_at = record["admission_manifest"]["entries"][0]["admitted_at"]
    records["1"]["first_started_at"] = admitted_at

    coverage = costs.report(record, resolve=resolve)["coverage"]

    assert coverage["status"] == "incomplete"
    assert coverage["can_confirm"] is False
    assert "1" in coverage["missing_or_ineligible_cases"]
    assert coverage["provider_cost_per_accepted_outcome"] is None


def test_explicit_admitted_zero_cost_is_distinct_from_missing_cost(planned):
    record, _, resolve = full_costs(planned, "0")
    saved = confirm_costs(record, resolve)
    metric = costs.report(saved, resolve=resolve)["coverage"]["provider_cost_per_accepted_outcome"]
    assert metric["amount"] == "0" and metric["provider_cost_total"] == "0"


def test_no_acceptance_has_no_division_and_later_source_change_requires_review(planned):
    record, records, resolve = full_costs(planned)
    records["1"]["accepted"] = False
    saved = confirm_costs(record, resolve)
    assert costs.report(saved, resolve=resolve)["coverage"]["provider_cost_per_accepted_outcome"] is None
    records["1"].update(accepted=True, version="b" * 64)
    assert costs.report(saved, resolve=resolve)["coverage"]["status"] == "incomplete"


def test_new_billing_or_allocation_invalidates_completeness_review(planned):
    record, _, resolve = full_costs(planned)
    saved = confirm_costs(record, resolve)
    ingest("new-billing-line", "1")
    coverage = costs.report(saved, resolve=resolve)["coverage"]
    assert coverage["can_confirm"] and coverage["status"] == "needs_review"
    assert coverage["provider_cost_per_accepted_outcome"] is None
    value = coverage_body(saved, resolve)
    value["operation_id"] = "review-new-billing-evidence"
    saved = confirm_costs(saved, resolve, value)
    amended = body(saved, operation_id="change-reviewed-case-share", shares=[
        {"case_id": str(i), "basis_points": 2000, "source_version": "a" * 64} for i in range(1, 5)])
    saved = save(saved, resolve, amended)
    assert costs.report(saved, resolve=resolve)["coverage"]["provider_cost_per_accepted_outcome"] is None


def test_mixed_currency_never_produces_a_per_accepted_cost(planned):
    record, _, resolve = full_costs(planned)
    ingest("euro-line", "3", "EUR")
    euro = next(row for row in costs.sources().values() if row["currency"] == "EUR")
    saved = save(record, resolve, body(record, operation_id="add-euro-cost-to-pilot", observation_id=euro["id"], billing_version=euro["version"]))
    coverage = costs.report(saved, resolve=resolve)["coverage"]
    assert coverage["currency"] is None and not coverage["can_confirm"]
    assert coverage["provider_cost_per_accepted_outcome"] is None
    with pytest.raises(ValueError, match="one common currency"):
        confirm_costs(saved, resolve)


@pytest.mark.parametrize("shares", [
    [{"case_id": "1", "basis_points": 6000, "source_version": "a" * 64}, {"case_id": "2", "basis_points": 6000, "source_version": "a" * 64}],
    [{"case_id": "1", "basis_points": 5000, "source_version": "a" * 64}, {"case_id": "1", "basis_points": 5000, "source_version": "a" * 64}],
])
def test_no_overallocation_or_duplicate_case(planned, shares):
    record, _, resolve = planned
    ingest()
    with pytest.raises(ValueError):
        save(record, resolve, body(record, shares=shares))
    assert not pilots.get(record["id"], "alice").get("provider_cost_allocations")


def test_new_correction_invalidates_then_requires_review_of_entire_line(planned):
    record, _, resolve = planned
    ingest()
    saved = save(record, resolve)
    ingest("credit", "-2", corrects="original")
    stale = costs.report(saved, resolve=resolve)
    assert stale["current_totals_by_currency"] == {}
    assert stale["allocations"][0]["status"] == "billing_changed"
    old = body(record)
    old["billing_version"] = saved["provider_cost_allocations"][old["observation_id"]]["source"]["version"]
    old.update(operation_id="new-review-old-source", expected_revision=saved["revision"])
    with pytest.raises(RecordConflict):
        save(saved, resolve, old)
    reviewed = save(saved, resolve, body(saved, operation_id="new-review-current-source"))
    result = costs.report(reviewed, resolve=resolve)
    assert result["current_totals_by_currency"] == {"USD": "8.000000001"}
    assert len(result["allocations"][0]["history"]) == 1
    assert result["allocations"][0]["source"]["correction_count"] == 1


def test_negative_net_provider_credit_is_not_reported_as_delivery_cost(planned):
    record, _, resolve = planned
    ingest(amount="1")
    saved = save(record, resolve)
    ingest("credit-over-balance", "-2", corrects="original")

    result = costs.report(saved, resolve=resolve)
    assert result["status"] == "partial"
    assert result["current_totals_by_currency"] == {}
    assert result["unsupported_credit_count"] == 1
    assert result["allocations"][0]["status"] == "unsupported_credit"

    with pytest.raises(ValueError, match="Provider credits cannot be allocated"):
        save(
            saved,
            resolve,
            body(saved, operation_id="review-negative-provider-credit"),
        )


def test_receipt_revision_and_source_changes_invalidate_allocations(planned):
    record, records, resolve = planned
    receipt = ingest()
    saved = save(record, resolve)
    records["1"]["version"] = "b" * 64
    assert costs.report(saved, resolve=resolve)["allocations"][0]["status"] == "case_changed"
    records["1"]["version"] = "a" * 64
    billing._RECEIPTS.update(receipt["id"], lambda r: r.update(batch_id="changed-metadata"),
                            expected_revision=receipt["revision"], action="synthetic_change", actor="user:alice")
    assert costs.report(saved, resolve=resolve)["allocations"][0]["status"] == "billing_changed"


def test_case_refresh_new_review_and_withdrawal_retain_history_without_stale_totals(planned):
    record, records, resolve = planned
    ingest()
    saved = save(record, resolve)
    records["1"]["version"] = "b" * 64
    value = body(saved, operation_id="review-changed-case-version")
    value["shares"][0]["source_version"] = "b" * 64
    saved = save(saved, resolve, value)
    result = costs.report(saved, resolve=resolve)
    assert result["status"] == "current"
    assert result["current_totals_by_currency"] == {"USD": "10.000000001"}
    saved = save(saved, resolve, body(saved, operation_id="withdraw-reviewed-allocation", shares=[]))
    result = costs.report(saved, resolve=resolve)
    assert result["current_totals_by_currency"] == {}
    assert len(result["allocations"][0]["history"]) == 2
    assert result["allocations"][0]["unallocated_cost"] == "10.000000001"


def test_mixed_currencies_remain_separate_and_partial_share_is_explicit(planned):
    record, _, resolve = planned
    ingest(amount="12")
    saved = save(record, resolve, body(record, shares=[{"case_id": "1", "basis_points": 5000, "source_version": "a" * 64}]))
    ingest("euro-line", "3", "EUR")
    euro = next(row for row in costs.sources().values() if row["currency"] == "EUR")
    saved = save(saved, resolve, body(saved, operation_id="allocate-separate-currency", observation_id=euro["id"], billing_version=euro["version"]))
    result = costs.report(saved, resolve=resolve)
    assert result["current_totals_by_currency"] == {"EUR": "3", "USD": "6"}
    assert next(row for row in result["allocations"] if row["currency"] == "USD")["unallocated_cost"] == "6"


def test_saved_allocation_corruption_is_not_reported_as_admitted_cost(planned):
    record, _, resolve = planned
    ingest()
    saved = save(record, resolve)
    altered = copy.deepcopy(saved)
    next(iter(altered["provider_cost_allocations"].values()))["source"]["net_cost"] = "100000"
    with pytest.raises(ValueError, match="version check"):
        costs.report(altered, resolve=resolve)


def test_allocation_history_reuses_current_source_reads_only_within_one_report(planned):
    record, records, resolve = planned
    ingest()
    saved = save(record, resolve)
    saved = save(saved, resolve, body(saved, operation_id="second-history-allocation"))
    reads = []

    def tracked(kind, reference):
        reads.append((kind, reference))
        return resolve(kind, reference)

    costs.report(saved, resolve=tracked)
    assert len(reads) == len(set(reads)) == len(record["cases"])
    reads.clear()
    records["1"]["version"] = "b" * 64
    refreshed = costs.report(saved, resolve=tracked)
    assert refreshed["status"] == "partial"
    assert refreshed["current_totals_by_currency"] == {}
    assert len(reads) == len(record["cases"])


def test_receipt_projection_only_keeps_bindings_for_selected_original(planned):
    ingest()
    ingest("other-line")
    observations, receipts = billing.default_service._report_observations()
    # A multi-line completed receipt must not be copied wholesale into every
    # source entry. Admission integrity itself is covered by the real service.
    combined = {**receipts[0], "observation_ids": [r["id"] for r in observations],
                "observation_bindings": [binding for r in receipts for binding in r["observation_bindings"]]}
    values = costs.sources(SimpleNamespace(_report_observations=lambda: (observations, [combined])))
    assert len(values) == 2
    for source in values.values():
        identifiers = {row["id"] for row in source["observations"]}
        assert all(binding["observation_id"] in identifiers for receipt in source["receipts"] for binding in receipt["observation_bindings"])
        assert len(source["receipts"][0]["observation_bindings"]) == 1


def test_correction_cannot_be_rebound_to_another_original_provider_line():
    ingest()
    ingest("other-line")
    ingest("credit", "-2", corrects="original")
    observations, _ = billing.default_service._report_observations()
    correction = next(row for row in observations if row["source_record_id"] == "credit")
    other = next(row for row in observations if row["source_record_id"] == "other-line")
    billing._OBSERVATIONS.update(correction["id"], lambda row: row.update(correction_of_observation_id=other["id"]),
        expected_revision=correction["revision"], action="synthetic_wrong_binding", actor="user:alice")
    with pytest.raises(ValueError, match="inconsistent source bindings"):
        costs.sources()


def test_incomplete_or_corrupt_receipts_never_become_cost(planned):
    record, _, resolve = planned
    receipt = ingest()
    source = next(iter(costs.sources().values()))
    observation = billing._OBSERVATIONS.get(source["id"])
    billing._OBSERVATIONS.update(source["id"], lambda r: r.update(source_cost="900000"),
                                expected_revision=observation["revision"], action="synthetic_corruption", actor="user:alice")
    with pytest.raises(billing.AICostStateError):
        costs.sources()
    billing._RECEIPTS.update(receipt["id"], lambda r: r.update(status="partial"),
                            expected_revision=receipt["revision"], action="synthetic_partial", actor="user:alice")
    assert costs.sources() == {}
    assert costs.report(record, resolve=resolve)["current_totals_by_currency"] == {}


def test_source_denial_hides_private_allocation_and_tenant_owner_checks(planned):
    record, _, resolve = planned
    ingest()
    saved = save(record, resolve)
    def denied(*args):
        raise PermissionError("private source")
    report = costs.report(saved, resolve=denied)
    assert report["allocations"] == [{"status": "source_unavailable"}]
    assert report["current_totals_by_currency"] == {}
    with pytest.raises(LookupError):
        costs.allocate(record["id"], body(saved), context="other", actor="user:other", resolve=resolve)
    with tenant_scope(tenant="other-workspace"):
        assert costs.sources() == {}
        with pytest.raises(LookupError):
            pilots.get(record["id"], "alice")


def test_cas_competing_case_allocations_cannot_double_count(planned):
    record, _, resolve = planned
    ingest()
    original = body(record)
    changed = {**copy.deepcopy(original), "operation_id": "competing-allocation-request"}
    changed["shares"][0]["case_id"] = "3"
    def run(value):
        with tenant_scope(tenant="cost-workspace"):
            try:
                return save(record, resolve, value)
            except RecordConflict:
                return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, [original, changed]))
    assert sum(result is not None for result in results) == 1
    result = costs.report(pilots.get(record["id"], "alice"), resolve=resolve)
    assert len(result["allocations"]) == 1
    assert result["current_totals_by_currency"] == {"USD": "10.000000001"}


def test_http_financial_authority_owner_context_and_confirmation_precede_source_read(planned, monkeypatch):
    record, _, resolve = planned
    ingest()
    value = body(record)
    rbac.set_role("user:alice", "admin")
    rbac.set_role("user:recovery", "admin")
    rbac.set_role("user:operator", "operator")
    monkeypatch.setattr(pilot_api, "context_for", lambda r: r.state.principal.sub)
    monkeypatch.setattr(pilot_api, "_resolver", lambda r: resolve)
    app = FastAPI()
    @app.middleware("http")
    async def identity(request: Request, next_call):
        subject = request.headers.get("X-Test-User", "alice")
        request.state.principal = SimpleNamespace(sub=subject, principal="user:" + subject)
        with tenant_scope(tenant="cost-workspace"):
            return await next_call(request)
    app.include_router(api.router)
    app.include_router(pilot_api.router)
    path = f"/api/v1/outcome-pilots/{record['id']}/provider-costs"
    original = costs.sources
    calls = []
    monkeypatch.setattr(costs, "sources", lambda *a: calls.append(True) or original(*a))
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1", "X-Lightwork-Pilot-Context": "alice"}) as client:
        assert client.get(path, headers={"X-Test-User": "operator", "X-Lightwork-Pilot-Context": "operator"}).status_code == 403
        assert client.get(path, headers={"X-Lightwork-Pilot-Context": "old"}).status_code == 409
        assert client.get(path.replace(record["id"], "OPL-missing")).status_code == 404
        assert client.put(path, json={**value, "confirm": False}).status_code == 422
        assert calls == []
        response = client.get(path)
        assert response.status_code == 200, response.text
        assert response.headers["Cache-Control"] == "private, no-store"
        assert len(response.json()["items"]) == 1
        response = client.put(path, json=value)
        assert response.status_code == 200, response.text
        coverage_payload = {"expected_revision": response.json()["revision"], "operation_id": "http-cost-coverage-review",
                            "coverage_version": "a" * 64, "currency": "USD", "note": "Reviewed synthetic scope", "confirm": False}
        assert client.put(path + "/coverage", json=coverage_payload).status_code == 422
        assert client.put(path + "/coverage", json={**coverage_payload, "confirm": True}).status_code == 422
        assert client.put(path + "/coverage", json=coverage_payload, headers={"X-Lightwork-Pilot-Context": "old-context"}).status_code == 409
        rbac.set_role("user:alice", "operator")
        assert client.put(path + "/coverage", json=coverage_payload).status_code == 403
        response = client.get(path.rsplit("/", 1)[0])
        assert response.status_code == 200, response.text
        assert response.json()["provider_costs"]["status"] == "unavailable"
        assert "synthetic-account" not in response.text
