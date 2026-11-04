"""In-app outcome-accounting projection boundaries."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick.governed_records import GovernedRecordStore
from maverick.outcome_accounting import COST_COVERAGE_FAMILIES, OutcomeAccounting
from maverick.paths import tenant_scope
from maverick_dashboard import outcome_accounting_api as api
from maverick_dashboard import outcome_pilots


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    service = OutcomeAccounting(store=GovernedRecordStore(
        "test_outcome_accounting_api", "OAA", "outcome_accounting",
    ))
    pilot_id = "OPL-pilot-one"
    plan_version = "a" * 64
    with tenant_scope(tenant="workspace-one"):
        alice = service.admit(
            admission_id=f"{pilot_id}:1", work_item_id="work-alice",
            acceptance_contract_ref=f"outcome-pilot:{pilot_id}:{plan_version}",
            owner_id="user:alice", actor="user:alice",
        )
        service.admit(
            admission_id="admission-bob", work_item_id="work-bob",
            acceptance_contract_ref="contract:one", owner_id="user:bob", actor="user:bob",
        )
    monkeypatch.setattr(api, "default_service", service)
    pilot = {
        "id": pilot_id,
        "plan_version": plan_version,
        "actor": "user:alice",
        "state": "frozen",
        "cases": [{"id": "1"}],
        "admission_manifest": {"manifest_sha256": "b" * 64},
    }
    monkeypatch.setattr(outcome_pilots, "get", lambda selected, context: pilot)
    monkeypatch.setattr(
        api.outcome_accounting_bridge,
        "require_complete_admission",
        lambda record, service=None: {"1": alice},
    )
    monkeypatch.setattr(api.config, "config_source_errors", lambda **kwargs: [])
    monkeypatch.setattr(api.config, "get_features", lambda: {"outcome_measurement": True})
    monkeypatch.setattr(api, "context_for", lambda request: "workspace-context")
    monkeypatch.setattr(api, "require_permission", lambda request, permission: None)
    monkeypatch.setattr(
        api, "has_permission",
        lambda request, permission: permission == "admin" and request.headers.get("X-Test-Admin") == "1",
    )
    monkeypatch.setattr(
        api, "caller_principal",
        lambda request: "user:" + request.headers.get("X-Test-User", "alice"),
    )
    app = FastAPI()

    @app.middleware("http")
    async def identity(request: Request, call_next):
        request.state.principal = SimpleNamespace(
            sub=request.headers.get("X-Test-User", "alice"),
            principal="user:" + request.headers.get("X-Test-User", "alice"),
        )
        with tenant_scope(tenant="workspace-one"):
            return await call_next(request)

    app.include_router(api.router)
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), alice["id"]


def test_named_user_sees_only_owned_admissions_and_no_store_metadata(client):
    browser, alice_id = client
    response = browser.get("/api/v1/outcome-accounting")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["admitted"] == 1
    assert [row["owner_id"] for row in body["records"]] == ["user:alice"]
    assert body["context"] == "workspace-context"
    assert response.headers["Cache-Control"] == "private, no-store"
    assert "_audit_pending" not in response.text
    assert browser.get(f"/api/v1/outcome-accounting/{alice_id}").status_code == 200


def test_local_dashboard_identity_reconciles_only_its_explicit_owner(monkeypatch):
    request = SimpleNamespace()
    monkeypatch.setattr(api, "caller_principal", lambda _request: None)

    assert api._caller_owns(request, {"owner_id": "local:dashboard"}) is True
    assert api._caller_owns(request, {"owner_id": "user:alice"}) is False


def test_other_owner_is_hidden_and_workspace_admin_can_view_portfolio(client):
    browser, alice_id = client
    assert browser.get(
        f"/api/v1/outcome-accounting/{alice_id}", headers={"X-Test-User": "bob"},
    ).status_code == 404
    response = browser.get(
        "/api/v1/outcome-accounting", headers={"X-Test-User": "bob", "X-Test-Admin": "1"},
    )
    assert response.status_code == 200
    assert response.json()["admitted"] == 2


def test_admin_cross_owner_reads_never_reconcile_or_mutate_the_other_owner(
    client, monkeypatch,
):
    browser, alice_id = client
    service = api.default_service
    with tenant_scope(tenant="workspace-one"):
        records = service.store.list(limit=10)
        bob_id = next(row["id"] for row in records if row["owner_id"] == "user:bob")
        alice_before = deepcopy(service.store.get(alice_id))
    calls = []

    def hostile_reconcile(
        request, context, record_id, *, service, owner_id,
    ):
        del request, context
        calls.append((record_id, owner_id))
        raw = service.store.get(record_id)
        if raw["owner_id"] == "user:alice":
            service.record_observation(
                record_id,
                expected_revision=raw["revision"],
                operation_id="hostile_admin_read_reconcile",
                actor="user:bob",
                source_id="hostile:cross-owner-read",
                source_version="f" * 64,
                result="unavailable",
                authoritative=True,
                summary="A cross-owner admin read must never write this evidence.",
            )
        return service.report(record_id, owner_id=owner_id)

    monkeypatch.setattr(
        api.outcome_accounting_bridge, "reconcile_record", hostile_reconcile,
    )
    headers = {"X-Test-User": "bob", "X-Test-Admin": "1"}
    portfolio = browser.get("/api/v1/outcome-accounting", headers=headers)
    assert portfolio.status_code == 200, portfolio.text
    assert {row["owner_id"] for row in portfolio.json()["records"]} == {
        "user:alice", "user:bob",
    }
    assert calls == [(bob_id, "user:bob")]

    other_detail = browser.get(
        f"/api/v1/outcome-accounting/{alice_id}", headers=headers,
    )
    assert other_detail.status_code == 200, other_detail.text
    assert other_detail.json()["owner_id"] == "user:alice"
    assert calls == [(bob_id, "user:bob")]

    for endpoint in (
        "/api/v1/outcome-accounting/cohort?pilot_id=OPL-pilot-one",
        "/api/v1/outcome-accounting/cohort/export?pilot_id=OPL-pilot-one",
    ):
        cohort = browser.get(
            endpoint,
            headers={**headers, "X-Lightwork-Pilot-Context": "workspace-context"},
        )
        assert cohort.status_code == 200, cohort.text
        assert calls == [(bob_id, "user:bob")]

    with tenant_scope(tenant="workspace-one"):
        alice_after = service.store.get(alice_id)
    assert alice_after["revision"] == alice_before["revision"]
    assert alice_after["observations"] == alice_before["observations"]
    assert alice_after["cost_events"] == alice_before["cost_events"]
    assert alice_after == alice_before


def test_other_owner_is_denied_before_detail_projection(client, monkeypatch):
    browser, alice_id = client
    monkeypatch.setattr(
        api.default_service, "_report_record",
        lambda *_args, **_kwargs: pytest.fail("unauthorized detail reached projection"),
    )
    response = browser.get(
        f"/api/v1/outcome-accounting/{alice_id}", headers={"X-Test-User": "bob"},
    )
    assert response.status_code == 404


def test_disabled_feature_fails_before_store_access(client, monkeypatch):
    browser, _ = client
    monkeypatch.setattr(api.config, "get_features", lambda: {"outcome_measurement": False})
    monkeypatch.setattr(
        api.default_service, "portfolio_report",
        lambda **kwargs: pytest.fail("disabled route reached the store"),
    )
    response = browser.get("/api/v1/outcome-accounting")
    assert response.status_code == 403


def test_stale_account_or_workspace_context_fails_before_store_access(client, monkeypatch):
    browser, _ = client
    monkeypatch.setattr(
        api.default_service, "portfolio_report",
        lambda **kwargs: pytest.fail("stale context reached the store"),
    )
    response = browser.get(
        "/api/v1/outcome-accounting",
        headers={"X-Lightwork-Pilot-Context": "previous-context"},
    )
    assert response.status_code == 409
    assert "workspace changed" in response.text


def test_non_ascii_context_header_is_refused_as_stale_not_a_server_error(client, monkeypatch):
    browser, _ = client
    monkeypatch.setattr(
        api.default_service, "portfolio_report",
        lambda **kwargs: pytest.fail("non-ASCII context reached the store"),
    )
    response = browser.get(
        "/api/v1/outcome-accounting",
        headers={"X-Lightwork-Pilot-Context": "workspace-contéxt".encode()},
    )
    assert response.status_code == 409
    assert "workspace changed" in response.text


def test_portfolio_api_is_paginated_and_never_embeds_full_event_histories(client):
    browser, _ = client
    headers = {"X-Test-Admin": "1"}
    first = browser.get("/api/v1/outcome-accounting?limit=1", headers=headers)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["admitted"] == 1
    assert body["page"]["has_more"] is True
    assert body["page"]["next_cursor"]
    assert "observations" not in body["records"][0]
    assert "events" not in body["records"][0]["costs"]

    second = browser.get(
        "/api/v1/outcome-accounting",
        params={"limit": 1, "cursor": body["page"]["next_cursor"]},
        headers=headers,
    )
    assert second.status_code == 200, second.text
    assert second.json()["records"][0]["id"] != body["records"][0]["id"]
    assert browser.get("/api/v1/outcome-accounting?limit=201", headers=headers).status_code == 422


def _cost_payload(**changes):
    value = {
        "expected_revision": 1,
        "operation_id": "ui-delivered-cost-one",
        "category": "support",
        "attempt_state": "succeeded",
        "basis": "observed",
        "total_relationship": "additional_to_current_total",
        "amount": "3",
        "currency": "USD",
        "unknown_reason": None,
        "quantity": "15",
        "unit": "minutes",
        "source_ref": "timesheet:support-one",
        "evidence_note": "Recorded from the reviewed support timesheet.",
        "allocation_method": "usage_weighted",
        "allocation_assumption": "Allocated by hands-on minutes for this admitted case.",
        "correction_reason": None,
        "complete_coverage": True,
        "coverage_declarations": {
            family: {
                "status": "included" if family in {"support", "allocation"} else "zero",
                "note": (
                    "Included in the recorded support allocation."
                    if family in {"support", "allocation"} else
                    "Reviewed evidence confirms zero for this family."
                ),
            }
            for family in COST_COVERAGE_FAMILIES
        },
    }
    value.update(changes)
    return value


def _baseline_payload(**changes):
    value = {
        "expected_revision": 0,
        "operation_id": "ui-baseline-evidence-one",
        "cost_basis": "observed",
        "cost_amount": "10",
        "currency": "USD",
        "cost_unknown_reason": None,
        "human_basis": "observed",
        "human_minutes": "60",
        "human_unknown_reason": None,
        "source_ref": "invoice:baseline-one",
        "evidence_note": "Observed pre-Lightwork invoice and time evidence.",
        "correction_reason": None,
    }
    value.update(changes)
    return value


def test_manual_cost_detail_is_not_added_after_an_all_in_total_unless_explicit(client):
    browser, alice_id = client
    headers = {"X-Lightwork-Pilot-Context": "workspace-context"}
    with tenant_scope(tenant="workspace-one"):
        current = api.default_service.store.get(alice_id)
        current = api.default_service.record_cost(
            alice_id,
            expected_revision=current["revision"],
            operation_id="current-all-in-delivered-total",
            actor="user:alice",
            category="other",
            attempt_state="succeeded",
            basis="observed",
            amount="10",
            currency="USD",
            source_ref="workflow:all-in-total",
            source_version="a" * 64,
            all_in_total=True,
        )

    included = _cost_payload(
        expected_revision=current["revision"],
        operation_id="manual-included-human-detail",
        category="human",
        amount="6",
        quantity="20",
        source_ref="timesheet:included-human-detail",
        allocation_method="direct",
        allocation_assumption=None,
        complete_coverage=False,
        coverage_declarations=None,
    )
    included.pop("total_relationship")  # The API's safe default is already included.
    response = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=included,
    )
    assert response.status_code == 200, response.text
    assert response.json()["outcome"]["costs"]["known_totals"] == {"USD": "10"}
    assert response.json()["outcome"]["costs"]["events"][-1]["aggregation"] == (
        "informational"
    )

    additional = _cost_payload(
        expected_revision=response.json()["outcome"]["revision"],
        operation_id="manual-additional-human-cost",
        category="human",
        total_relationship="additional_to_current_total",
        amount="6",
        quantity="20",
        source_ref="timesheet:additional-human-cost",
        allocation_method="direct",
        allocation_assumption=None,
        complete_coverage=False,
        coverage_declarations=None,
    )
    response = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=additional,
    )
    assert response.status_code == 200, response.text
    assert response.json()["outcome"]["costs"]["known_totals"] == {"USD": "16"}
    assert response.json()["outcome"]["costs"]["events"][-1]["aggregation"] == (
        "additive"
    )


def test_included_cost_detail_requires_current_matching_all_in_total(client):
    browser, alice_id = client
    headers = {"X-Lightwork-Pilot-Context": "workspace-context"}
    payload = _cost_payload(
        total_relationship="included_in_current_total",
        complete_coverage=False,
        coverage_declarations=None,
    )
    response = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=payload,
    )
    assert response.status_code == 422
    assert "requires a current all-in total" in response.text

    invalid = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json={**payload, "total_relationship": "maybe_included"},
    )
    assert invalid.status_code == 422


def test_cohort_value_api_withholds_incomplete_roi_and_exports_reconciled_records(client):
    browser, alice_id = client
    headers = {"X-Lightwork-Pilot-Context": "workspace-context"}

    initial = browser.get(
        "/api/v1/outcome-accounting/cohort?pilot_id=OPL-pilot-one", headers=headers,
    )
    assert initial.status_code == 200, initial.text
    assert initial.json()["admitted"] == 1
    assert initial.json()["comparison"]["cost"]["status"] == "unavailable"
    assert initial.json()["comparison"]["cost"]["net_savings"] is None
    assert initial.json()["comparison"]["cost"]["roi_percent"] is None

    cost = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=_cost_payload(),
    )
    assert cost.status_code == 200, cost.text
    assert cost.json()["outcome"]["costs"]["known_totals"] == {"USD": "3"}
    assert cost.json()["outcome"]["costs"]["events"][0]["source_assurance"] == "operator_assertion"
    assert cost.json()["outcome"]["costs"]["events"][0]["evidence_note"] == (
        "Recorded from the reviewed support timesheet."
    )
    # An exact delivery retry is idempotent even after the source entry exists.
    duplicate = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=_cost_payload(),
    )
    assert duplicate.status_code == 200, duplicate.text
    assert duplicate.json()["outcome"]["revision"] == cost.json()["outcome"]["revision"]

    baseline = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/baseline",
        headers=headers,
        json=_baseline_payload(),
    )
    assert baseline.status_code == 200, baseline.text
    assert baseline.json()["comparison"]["cost"]["status"] == "measured"
    assert baseline.json()["comparison"]["cost"]["net_savings"] == "7"
    assert baseline.json()["comparison"]["cost"]["roi_percent"] == "70"

    commercial = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/commercial",
        headers=headers,
        json={
            "expected_revision": baseline.json()["value_revision"],
            "operation_id": "ui-renewal-evidence-one",
            "kind": "renewal",
            "stage": "proposed",
            "basis": "estimated",
            "amount": "100",
            "currency": "USD",
            "unknown_reason": None,
            "source_ref": "crm:renewal-one",
            "note": "Renewal proposal is tracked separately from savings.",
            "correction_reason": None,
        },
    )
    assert commercial.status_code == 200, commercial.text

    report = browser.get(
        "/api/v1/outcome-accounting/cohort?pilot_id=OPL-pilot-one", headers=headers,
    ).json()
    assert report["categories"] == {
        "accepted": 0, "cancelled": 0, "failed": 0, "rejected": 0, "unresolved": 1,
    }
    assert report["costs"]["category_totals"] == {"support": {"USD": "3"}}
    assert report["comparison"]["cost"]["status"] == "measured"
    assert report["comparison"]["cost"]["net_savings"] == "7"
    assert len(report["commercial"]["renewals"]) == 1
    assert report["comparison"]["commercial_records_included"] is False

    exported = browser.get(
        "/api/v1/outcome-accounting/cohort/export?pilot_id=OPL-pilot-one", headers=headers,
    )
    assert exported.status_code == 200, exported.text
    exported_body = exported.json()
    assert exported_body["schema"] == "lightwork.outcome-value-export.v1"
    assert exported_body["cohort_sha256"]
    envelope = exported_body["export_envelope"]
    assert envelope == {
        "schema": "lightwork.outcome-value-export-envelope.v1",
        "digest_algorithm": "SHA-256",
        "digest_encoding": "lowercase-hex",
        "canonicalization": "lightwork.canonical-json-tree-f64-utf8hex.v1",
        "node_encoding": "tagged-arrays-null-[tag]-others-[tag,value]",
        "object_encoding": "sorted-[utf8hex-key,node]-pairs",
        "string_encoding": "utf-8-lowercase-hex",
        "number_encoding": "ieee-754-binary64-big-endian-lowercase-hex",
        "object_key_order": "utf-8-byte-lexicographic",
        "array_order": "preserved",
        "serialization": "compact-json-utf-8",
        "excluded_fields": ["context", "export_envelope.digest_sha256"],
        "digest_sha256": api._export_envelope_digest(exported_body),
    }
    for path, replacement in (
        (("pilot_id",), "OPL-pilot-tampered"),
        (("plan_version",), "c" * 64),
        (("admission_manifest_sha256",), "d" * 64),
        (("cases", 0, "outcome", "work_item_id"), "work-tampered"),
    ):
        tampered = deepcopy(exported_body)
        target = tampered
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = replacement
        assert api._export_envelope_digest(tampered) != envelope["digest_sha256"]
    other_request_context = deepcopy(exported_body)
    other_request_context["context"] = "another-request-context"
    assert api._export_envelope_digest(other_request_context) == envelope["digest_sha256"]
    assert exported.headers["Content-Disposition"] == (
        'attachment; filename="lightwork-outcome-value-report.json"'
    )
    assert "events" not in exported_body["cases"][0]["outcome"]["costs"]


def test_cohort_api_withholds_an_extreme_but_valid_ratio(client):
    browser, alice_id = client
    headers = {"X-Lightwork-Pilot-Context": "workspace-context"}
    cost = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=_cost_payload(amount="999999999999999999"),
    )
    assert cost.status_code == 200, cost.text
    baseline = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/baseline",
        headers=headers,
        json=_baseline_payload(cost_amount="0.000000000001"),
    )
    assert baseline.status_code == 200, baseline.text

    response = browser.get(
        "/api/v1/outcome-accounting/cohort?pilot_id=OPL-pilot-one",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    report = response.json()
    case_cost = report["cases"][0]["comparison"]["cost"]
    assert case_cost["status"] == "unavailable"
    assert case_cost["overflow"] is True
    assert case_cost["net_savings"] is None
    assert case_cost["roi_percent"] is None
    assert "cost_comparison_overflow" in (
        report["cases"][0]["comparison"]["missing_components"]
    )
    assert report["comparison"]["cost"]["status"] == "unavailable"
    assert report["comparison"]["cost"]["overflow"] is True


def test_complete_cost_api_requires_truthful_exact_family_declarations(client):
    browser, alice_id = client
    headers = {"X-Lightwork-Pilot-Context": "workspace-context"}
    missing = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=_cost_payload(coverage_declarations=None),
    )
    assert missing.status_code == 422

    incomplete = _cost_payload()["coverage_declarations"]
    incomplete.pop("allocation")
    wrong_shape = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=_cost_payload(coverage_declarations=incomplete),
    )
    assert wrong_shape.status_code == 422

    unknown = _cost_payload()["coverage_declarations"]
    unknown["setup"] = {
        "status": "unknown",
        "note": "Setup evidence has not been reviewed.",
    }
    unresolved = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=_cost_payload(coverage_declarations=unknown),
    )
    assert unresolved.status_code == 422

    false_zero = _cost_payload()["coverage_declarations"]
    false_zero["support"] = {
        "status": "zero",
        "note": "Incorrectly claims the recorded support cost is zero.",
    }
    contradictory = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=_cost_payload(coverage_declarations=false_zero),
    )
    assert contradictory.status_code == 422
    assert "cannot be declared zero" in contradictory.text


def test_api_keeps_two_same_owner_pilot_manifests_isolated(client, monkeypatch):
    browser, first_id = client
    service = api.default_service
    second_pilot_id = "OPL-pilot-two"
    second_plan = "c" * 64
    with tenant_scope(tenant="workspace-one"):
        second = service.admit(
            admission_id=f"{second_pilot_id}:1",
            work_item_id="work-alice-second-pilot",
            acceptance_contract_ref=f"outcome-pilot:{second_pilot_id}:{second_plan}",
            owner_id="user:alice",
            actor="user:alice",
        )
        first = service.store.get(first_id)
    pilots = {
        "OPL-pilot-one": {
            "id": "OPL-pilot-one", "plan_version": "a" * 64,
            "actor": "user:alice", "state": "frozen", "cases": [{"id": "1"}],
            "admission_manifest": {"manifest_sha256": "b" * 64},
        },
        second_pilot_id: {
            "id": second_pilot_id, "plan_version": second_plan,
            "actor": "user:alice", "state": "frozen", "cases": [{"id": "1"}],
            "admission_manifest": {"manifest_sha256": "d" * 64},
        },
    }
    admissions = {
        "OPL-pilot-one": {"1": first},
        second_pilot_id: {"1": second},
    }
    monkeypatch.setattr(
        outcome_pilots, "get", lambda selected, context: pilots[selected],
    )
    monkeypatch.setattr(
        api.outcome_accounting_bridge,
        "require_complete_admission",
        lambda record, service=None: admissions[record["id"]],
    )
    headers = {"X-Lightwork-Pilot-Context": "workspace-context"}
    first_report = browser.get(
        "/api/v1/outcome-accounting/cohort?pilot_id=OPL-pilot-one", headers=headers,
    )
    second_report = browser.get(
        f"/api/v1/outcome-accounting/cohort?pilot_id={second_pilot_id}", headers=headers,
    )
    assert first_report.status_code == 200, first_report.text
    assert second_report.status_code == 200, second_report.text
    assert [row["outcome"]["id"] for row in first_report.json()["cases"]] == [first_id]
    assert [row["outcome"]["id"] for row in second_report.json()["cases"]] == [second["id"]]
    assert first_report.json()["cohort_binding"]["record_ids_sha256"] != (
        second_report.json()["cohort_binding"]["record_ids_sha256"]
    )


def test_cost_correction_is_documented_and_counted_once_through_api(client):
    browser, alice_id = client
    headers = {"X-Lightwork-Pilot-Context": "workspace-context"}
    first = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=_cost_payload(),
    )
    revision = first.json()["outcome"]["revision"]
    undocumented = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=_cost_payload(
            expected_revision=revision,
            operation_id="ui-cost-correction-bad",
            amount="4",
        ),
    )
    assert undocumented.status_code == 422
    corrected = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=_cost_payload(
            expected_revision=revision,
            operation_id="ui-cost-correction-good",
            amount="4",
            correction_reason="The first timesheet omitted one support unit.",
        ),
    )
    assert corrected.status_code == 200, corrected.text
    costs = corrected.json()["outcome"]["costs"]
    assert costs["known_totals"] == {"USD": "4"}
    assert costs["event_count"] == 1
    assert costs["superseded_event_count"] == 1
    assert costs["events"][1]["correction_reason"].startswith("The first")

    duplicate_correction = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=_cost_payload(
            expected_revision=corrected.json()["outcome"]["revision"],
            operation_id="ui-cost-correction-good",
            amount="4",
            correction_reason="The first timesheet omitted one support unit.",
        ),
    )
    assert duplicate_correction.status_code == 200, duplicate_correction.text
    retried_costs = duplicate_correction.json()["outcome"]["costs"]
    assert retried_costs["known_totals"] == {"USD": "4"}
    assert retried_costs["event_count"] == 1
    assert retried_costs["superseded_event_count"] == 1
    changed_retry = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=_cost_payload(
            expected_revision=revision,
            operation_id="ui-cost-correction-good",
            amount="5",
            correction_reason="The first timesheet omitted one support unit.",
        ),
    )
    assert changed_retry.status_code == 409


def test_baseline_and_commercial_corrections_are_exactly_retryable(client):
    browser, alice_id = client
    headers = {"X-Lightwork-Pilot-Context": "workspace-context"}
    first = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/baseline",
        headers=headers,
        json=_baseline_payload(),
    )
    assert first.status_code == 200, first.text
    baseline_revision = first.json()["value_revision"]
    baseline_correction = _baseline_payload(
        expected_revision=baseline_revision,
        operation_id="ui-baseline-correction-one",
        cost_amount="12",
        correction_reason="The reviewed invoice included a late adjustment.",
    )
    corrected = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/baseline",
        headers=headers,
        json=baseline_correction,
    )
    assert corrected.status_code == 200, corrected.text
    retried = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/baseline",
        headers=headers,
        json={**baseline_correction, "expected_revision": corrected.json()["value_revision"]},
    )
    assert retried.status_code == 200, retried.text
    assert retried.json()["value_revision"] == corrected.json()["value_revision"]
    assert len(retried.json()["baseline_history"]) == 2

    commercial = {
        "expected_revision": corrected.json()["value_revision"],
        "operation_id": "ui-commercial-original-one",
        "kind": "renewal",
        "stage": "proposed",
        "basis": "estimated",
        "amount": "100",
        "currency": "USD",
        "unknown_reason": None,
        "source_ref": "crm:renewal-retry-one",
        "note": "Initial proposal.",
        "correction_reason": None,
    }
    original = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/commercial",
        headers=headers,
        json=commercial,
    )
    assert original.status_code == 200, original.text
    commercial_correction = {
        **commercial,
        "expected_revision": original.json()["value_revision"],
        "operation_id": "ui-commercial-correction-one",
        "amount": "120",
        "note": "Reviewed proposal.",
        "correction_reason": "The account owner approved the revised scope.",
    }
    revised = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/commercial",
        headers=headers,
        json=commercial_correction,
    )
    assert revised.status_code == 200, revised.text
    retried = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/commercial",
        headers=headers,
        json={**commercial_correction, "expected_revision": revised.json()["value_revision"]},
    )
    assert retried.status_code == 200, retried.text
    assert retried.json()["value_revision"] == revised.json()["value_revision"]
    assert sum(row["current"] for row in retried.json()["renewals"]) == 1


def test_value_mutations_require_current_context_and_owner(client):
    browser, alice_id = client
    assert browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/baseline",
        json=_baseline_payload(),
    ).status_code == 409
    response = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/baseline",
        headers={
            "X-Test-User": "bob",
            "X-Lightwork-Pilot-Context": "workspace-context",
        },
        json=_baseline_payload(),
    )
    assert response.status_code == 404


def test_cross_owner_admin_portfolio_access_cannot_mutate_value_evidence(client):
    browser, alice_id = client
    headers = {
        "X-Test-User": "bob",
        "X-Test-Admin": "1",
        "X-Lightwork-Pilot-Context": "workspace-context",
    }
    attempts = (
        ("baseline", _baseline_payload()),
        (
            "commercial",
            {
                "expected_revision": 0,
                "operation_id": "cross-owner-commercial-one",
                "kind": "renewal",
                "stage": "proposed",
                "basis": "estimated",
                "amount": "999",
                "currency": "USD",
                "unknown_reason": None,
                "source_ref": "crm:cross-owner-renewal",
                "note": "A workspace administrator must not change another owner's evidence.",
                "correction_reason": None,
            },
        ),
        ("costs", _cost_payload(amount="999")),
    )

    for route, payload in attempts:
        response = browser.post(
            f"/api/v1/outcome-accounting/{alice_id}/{route}",
            headers=headers,
            json=payload,
        )
        assert response.status_code == 404, (route, response.text)

    with tenant_scope(tenant="workspace-one"):
        outcome = api.default_service.report(alice_id, owner_id="user:alice")
        value = api._values().case_report(alice_id, owner_id="user:alice")
    assert outcome["revision"] == 1
    assert outcome["costs"]["events"] == []
    assert value["value_revision"] == 0
    assert value["baseline_history"] == []
    assert value["renewals"] == []
    assert value["expansions"] == []


def test_in_app_cost_rejects_unexplained_allocation_and_fake_settlement(client):
    browser, alice_id = client
    headers = {"X-Lightwork-Pilot-Context": "workspace-context"}
    unexplained = _cost_payload(allocation_assumption=None)
    response = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=unexplained,
    )
    assert response.status_code == 422
    fake_settlement = _cost_payload(
        operation_id="ui-fake-settlement-one",
        basis="settled",
    )
    response = browser.post(
        f"/api/v1/outcome-accounting/{alice_id}/costs",
        headers=headers,
        json=fake_settlement,
    )
    assert response.status_code == 422


def test_in_app_semantic_provider_cost_can_complete_observed_coverage(client):
    browser, record_id = client
    declarations = {
        family: {
            "status": "included" if family == "provider_usage" else "zero",
            "note": (
                "Reviewed provider evidence."
                if family == "provider_usage" else
                "Reviewed evidence confirms zero."
            ),
        }
        for family in COST_COVERAGE_FAMILIES
    }
    response = browser.post(
        f"/api/v1/outcome-accounting/{record_id}/costs",
        headers={"X-Lightwork-Pilot-Context": "workspace-context"},
        json=_cost_payload(
            category="inference",
            quantity=None,
            unit=None,
            source_ref="operator:provider-usage-one",
            allocation_method="direct",
            allocation_assumption=None,
            coverage_declarations=declarations,
        ),
    )
    assert response.status_code == 200, response.text
    assert response.json()["outcome"]["costs"]["complete"] is True
    assert response.json()["outcome"]["costs"]["settlement_status"] == "observed"


def test_manual_api_cannot_replace_source_owned_cost(client):
    browser, record_id = client
    with tenant_scope(tenant="workspace-one"):
        service = api.default_service
        raw = service.store.get(record_id)
        raw = api.outcome_accounting_bridge._cost(
            service,
            raw,
            operation_id="bridge-owned-projection-one",
            actor="system:reconciler",
            category="inference",
            amount="8",
            currency="USD",
            source_ref="provider:managed-one",
            source_version="c" * 64,
            attempt_state="succeeded",
            basis="observed",
            source_assurance="application_observation",
        )
    response = browser.post(
        f"/api/v1/outcome-accounting/{record_id}/costs",
        headers={"X-Lightwork-Pilot-Context": "workspace-context"},
        json=_cost_payload(
            expected_revision=raw["revision"],
            operation_id="manual-takeover-attempt-one",
            category="inference",
            amount="0",
            quantity=None,
            unit=None,
            source_ref="provider:managed-one",
            correction_reason="Replace the source projection.",
            allocation_method="direct",
            allocation_assumption=None,
            complete_coverage=False,
            coverage_declarations=None,
        ),
    )
    assert response.status_code == 422
    with tenant_scope(tenant="workspace-one"):
        assert service.report(record_id)["costs"]["known_totals"] == {"USD": "8"}


def test_manual_api_reserves_lightwork_cost_namespaces(client):
    browser, record_id = client
    response = browser.post(
        f"/api/v1/outcome-accounting/{record_id}/costs",
        headers={"X-Lightwork-Pilot-Context": "workspace-context"},
        json=_cost_payload(
            source_ref="outcome-pilot:OPL-pilot-one:1:runtime",
            complete_coverage=False,
            coverage_declarations=None,
        ),
    )
    assert response.status_code == 422
    assert "maintained by Lightwork" in response.text


def test_value_read_reconciles_owned_record_only(client, monkeypatch):
    browser, record_id = client
    calls = []
    original = api.outcome_accounting_bridge.reconcile_record

    def tracked(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)

    monkeypatch.setattr(api.outcome_accounting_bridge, "reconcile_record", tracked)
    response = browser.get(
        f"/api/v1/outcome-accounting/{record_id}/value",
        headers={"X-Lightwork-Pilot-Context": "workspace-context"},
    )
    assert response.status_code == 200, response.text
    assert [args[2] for args, _ in calls] == [record_id]

    calls.clear()
    response = browser.get(
        f"/api/v1/outcome-accounting/{record_id}/value",
        headers={
            "X-Test-User": "bob",
            "X-Test-Admin": "1",
            "X-Lightwork-Pilot-Context": "workspace-context",
        },
    )
    assert response.status_code == 200, response.text
    assert calls == []
