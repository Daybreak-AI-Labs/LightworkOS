"""End-to-end projection from an in-app pilot into complete accounting."""
from __future__ import annotations

import copy

import pytest
from maverick.governed_records import GovernedRecordStore
from maverick.outcome_accounting import COST_COVERAGE_FAMILIES, OutcomeAccounting
from maverick.outcome_value_reporting import OutcomeValueReporting
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict
from maverick_dashboard import outcome_accounting_bridge as bridge
from maverick_dashboard import outcome_pilot_costs, outcome_pilot_sources, outcome_pilots


def _source(_kind, reference):
    return {
        "unstarted": True, "input_version": f"input-{reference}",
        "first_started_at": None,
    }


def _pilot(service=None):
    pilot = {
        "id": "OPL-" + "1" * 48, "plan_version": "2" * 64, "state": "frozen",
        "actor": "user:owner@example.test",
        "cases": [{"id": str(index), "kind": "goal", "reference": str(index),
                   "input_version": f"input-{index}", "measurement": None}
                  for index in range(1, 4)],
    }
    pilot["admission_manifest"] = outcome_pilots.admission_manifest(pilot)
    if service is not None:
        with tenant_scope(tenant="workspace-one"):
            pilot["admission_manifest"] = bridge.admit_pilot(
                pilot, resolve=_source, service=service,
            )
    return pilot


def _service(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    return OutcomeAccounting(store=GovernedRecordStore(
        "test_outcome_accounting_bridge", "OAB", "outcome-accounting",
    ))


def _coverage(*included):
    selected = set(included) or {"all"}
    return {
        family: {
            "status": "included" if family in selected or "all" in selected else "zero",
            "note": (
                "Included in the operator-reported all-in workflow cost."
                if family in selected or "all" in selected else
                "The reviewed source confirms zero for this family."
            ),
        }
        for family in COST_COVERAGE_FAMILIES
    }


def _started_source(pilot, source, case_id="1"):
    case = next(row for row in pilot["cases"] if row["id"] == case_id)
    admission = next(
        row for row in pilot["admission_manifest"]["entries"]
        if row["case_id"] == case_id
    )
    source.setdefault("unstarted", False)
    source.setdefault("input_version", case["input_version"])
    source.setdefault("first_started_at", admission["admitted_at"] + 1)
    return source


def test_frozen_plan_admits_every_case_and_exact_retry_does_not_duplicate(tmp_path, monkeypatch):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot()
    with tenant_scope(tenant="workspace-one"):
        first = bridge.admit_pilot(pilot, resolve=_source, service=service)
        assert bridge.admit_pilot(pilot, resolve=_source, service=service) == first
        pilot["admission_manifest"] = first
        bridge.require_complete_admission(pilot, service=service)
        portfolio = service.portfolio_report()
    assert len(first["entries"]) == 3
    assert portfolio["admitted"] == 3
    assert portfolio["categories"]["unresolved"] == 3
    assert portfolio["costs"]["incomplete_records"] == 3


def test_read_reconciliation_handles_admitted_case_before_first_measurement(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    source = {
        "version": "a" * 64,
        "finished": False,
        "accepted": None,
        "reviewer": None,
        "status": "queued",
        "runtime_cost_usd": None,
    }
    monkeypatch.setattr(outcome_pilots, "get", lambda pilot_id, context: pilot)
    monkeypatch.setattr(
        outcome_pilot_sources, "resolve", lambda request, kind, reference: source,
    )
    record_id = pilot["admission_manifest"]["entries"][0]["accounting_record_id"]

    with tenant_scope(tenant="workspace-one"):
        report = bridge.reconcile_record(
            object(), "workspace-one", record_id,
            service=service, owner_id="user:owner@example.test",
        )
        retried = bridge.reconcile_record(
            object(), "workspace-one", record_id,
            service=service, owner_id="user:owner@example.test",
        )

    assert report["technical_outcome"]["status"] == "unresolved"
    assert report["costs"]["complete"] is False
    assert report["costs"]["events"] == []
    assert retried["revision"] == report["revision"]


def test_reconciliation_cannot_write_when_pilot_is_outside_current_context(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    record_id = pilot["admission_manifest"]["entries"][0]["accounting_record_id"]
    with tenant_scope(tenant="workspace-one"):
        before = copy.deepcopy(service.store.get(record_id))

    monkeypatch.setattr(
        outcome_pilots,
        "get",
        lambda pilot_id, context: (_ for _ in ()).throw(
            LookupError("This pilot is unavailable in your account and workspace.")
        ),
    )
    with tenant_scope(tenant="workspace-one"):
        with pytest.raises(LookupError, match="unavailable"):
            bridge.reconcile_record(
                object(), "another-workspace", record_id,
                service=service, owner_id="user:owner@example.test",
            )
        after = service.store.get(record_id)

    assert after == before


def test_admission_refuses_work_that_started_after_freeze_before_any_ledger_write(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot()

    def started(_kind, reference):
        return {
            "unstarted": False, "input_version": f"input-{reference}",
            "first_started_at": 1.0,
        }

    with tenant_scope(tenant="workspace-one"):
        with pytest.raises(RecordConflict, match="Work started before"):
            bridge.admit_pilot(pilot, resolve=started, service=service)
        assert service.store.list() == []


def test_admission_refuses_work_starting_at_the_admission_timestamp(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    monkeypatch.setattr(service.store, "authoritative_time", lambda: 100.0)
    pilot = _pilot()
    pilot["cases"] = pilot["cases"][:1]
    pilot["admission_manifest"] = outcome_pilots.admission_manifest(pilot)
    calls = [0]

    def starts_during_admission(_kind, reference):
        calls[0] += 1
        if calls[0] == 1:
            return {
                "unstarted": True,
                "input_version": f"input-{reference}",
                "first_started_at": None,
            }
        return {
            "unstarted": False,
            "input_version": f"input-{reference}",
            "first_started_at": 100.0,
        }

    with tenant_scope(tenant="workspace-one"):
        with pytest.raises(RecordConflict, match="Work started before"):
            bridge.admit_pilot(
                pilot, resolve=starts_during_admission, service=service,
            )




def test_sync_fails_closed_before_events_when_any_manifest_admission_is_missing(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64, "criteria_met": True,
        "evidence": "Reviewed task result and sign-off.", "ai_total_cost": "3",
        "human_cost": "5", "rework_cost": "2", "ai_hands_on_minutes": 10,
        "review_minutes": 5, "rework_minutes": 2, "currency": "USD",
        "cost_coverage": _coverage(),
    }
    source = {
        "version": "a" * 64, "finished": True, "accepted": True,
        "reviewer": "user:reviewer@example.test", "status": "done",
        "runtime_cost_usd": None,
    }
    missing_id = pilot["admission_manifest"]["entries"][2]["accounting_record_id"]
    original_get = service.store.get

    def missing(record_id):
        return None if record_id == missing_id else original_get(record_id)

    with tenant_scope(tenant="workspace-one"):
        before = copy.deepcopy(service.store.list())
        monkeypatch.setattr(service.store, "get", missing)
        with pytest.raises(RecordConflict, match="missing its exact durable"):
            bridge.sync_case(
                pilot, "1", _started_source(pilot, source), source_operation_id="must-not-partially-sync",
                actor="user:owner@example.test", service=service,
            )
        assert service.store.list() == before


def test_observation_sync_retains_decision_components_and_corrections(tmp_path, monkeypatch):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64, "criteria_met": True,
        "evidence": "Reviewed task result and sign-off.", "ai_total_cost": "25",
        "human_cost": "10", "rework_cost": None, "ai_hands_on_minutes": 20,
        "review_minutes": 10, "rework_minutes": 5, "currency": "USD",
        "cost_coverage": _coverage(),
    }
    source = {"version": "a" * 64, "finished": True, "accepted": True,
              "reviewer": "user:reviewer@example.test", "status": "done",
              "runtime_cost_usd": 4}
    with tenant_scope(tenant="workspace-one"):
        first = bridge.sync_case(
            pilot, "1", _started_source(pilot, source), source_operation_id="pilot-observation-one",
            actor="user:owner@example.test", service=service,
        )
        retried = bridge.sync_case(
            pilot, "1", _started_source(pilot, source), source_operation_id="pilot-observation-one",
            actor="user:owner@example.test", service=service,
        )
        assert retried["revision"] == first["revision"]
        assert first["technical_outcome"]["status"] == "verified"
        assert first["business_outcome"]["status"] == "accepted"
        assert first["costs"]["known_totals"] == {"USD": "25"}
        assert first["costs"]["informational_event_count"] == 3
        assert first["costs"]["unknown_event_count"] == 1

        pilot["cases"][0]["measurement"].update(
            source_version="b" * 64, criteria_met=True, evidence="Corrected source rejected the result.",
        )
        corrected_source = {**source, "version": "b" * 64, "accepted": False,
                            "reviewer": "user:second-reviewer@example.test"}
        corrected = bridge.sync_case(
            pilot, "1", _started_source(pilot, corrected_source), source_operation_id="pilot-observation-two",
            actor="user:owner@example.test", service=service,
        )
    assert corrected["technical_outcome"]["status"] == "failed"
    assert corrected["business_outcome"]["status"] == "rejected"
    assert corrected["observations"][0]["current_reason"] == "superseded"
    assert [row["decision"] for row in corrected["decisions"]] == ["accepted", "rejected"]
    assert corrected["decisions"][0]["current"] is False


def test_bridge_requires_explicit_family_evidence_before_cost_completion(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64,
        "criteria_met": True,
        "evidence": "Reviewed task result and sign-off.",
        "ai_total_cost": "9",
        "human_cost": None,
        "rework_cost": None,
        "ai_hands_on_minutes": 10,
        "review_minutes": 5,
        "rework_minutes": 0,
        "currency": "USD",
    }
    source = {
        "version": "a" * 64,
        "finished": True,
        "accepted": True,
        "reviewer": "user:reviewer@example.test",
        "status": "done",
        "runtime_cost_usd": None,
    }
    with tenant_scope(tenant="workspace-one"):
        incomplete = bridge.sync_case(
            pilot, "1", _started_source(pilot, source), source_operation_id="family-evidence-boundary",
            actor="user:owner@example.test", service=service,
        )
        pilot["cases"][0]["measurement"]["cost_coverage"] = _coverage()
        complete = bridge.sync_case(
            pilot, "1", _started_source(pilot, source), source_operation_id="family-evidence-boundary",
            actor="user:owner@example.test", service=service,
        )

    assert incomplete["costs"]["known_totals"] == {"USD": "9"}
    assert incomplete["costs"]["coverage_complete"] is False
    assert incomplete["costs"]["complete"] is False
    assert complete["costs"]["known_totals"] == {"USD": "9"}
    assert complete["costs"]["coverage_complete"] is True
    assert complete["costs"]["complete"] is True
    coverage = [
        row for row in complete["costs"]["events"]
        if row["current"] and row["aggregation"] == "coverage"
    ]
    assert len(coverage) == 1
    assert set(coverage[0]["coverage_declarations"]) == set(COST_COVERAGE_FAMILIES)


def test_bridge_preserves_missing_human_minutes_and_value_report_withholds_roi(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    values = OutcomeValueReporting(
        accounting=service,
        store=GovernedRecordStore(
            "test_bridge_value_evidence", "OBV", "outcome_value_evidence",
        ),
    )
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64,
        "criteria_met": True,
        "evidence": "Cost is observed, but delivered human time is unavailable.",
        "ai_total_cost": "3",
        "human_cost": None,
        "rework_cost": None,
        "ai_hands_on_minutes": None,
        "review_minutes": None,
        "rework_minutes": None,
        "currency": "USD",
        "cost_coverage": _coverage(),
    }
    source = {
        "version": "a" * 64,
        "finished": True,
        "accepted": True,
        "reviewer": "user:reviewer@example.test",
        "status": "done",
        "runtime_cost_usd": None,
    }
    with tenant_scope(tenant="workspace-one"):
        synced = bridge.sync_case(
            pilot, "1", _started_source(pilot, source), source_operation_id="missing-human-time-boundary",
            actor="user:owner@example.test", service=service,
        )
        labour = [
            row for row in synced["costs"]["events"]
            if row["category"] in {"human", "rework"}
        ]
        assert labour and all(row["quantity"] is None for row in labour)
        values.record_baseline(
            synced["id"], expected_revision=0,
            operation_id="bridge-baseline-evidence-one",
            actor="user:owner@example.test",
            cost_basis="observed", cost_amount="10", currency="USD",
            cost_unknown_reason=None,
            human_basis="observed", human_minutes="60", human_unknown_reason=None,
            source_ref="baseline:bridge-missing-time", source_version="b" * 64,
            evidence_note="Observed baseline includes cost and human time.",
        )
        report = values.case_report(
            synced["id"], owner_id="user:owner@example.test",
        )

    assert synced["costs"]["complete"] is True
    assert report["comparison"]["human_effort"]["status"] == "unavailable"
    assert report["comparison"]["cost"]["status"] == "unavailable"
    assert report["comparison"]["cost"]["net_savings"] is None
    assert report["comparison"]["cost"]["roi_percent"] is None
    assert report["comparison"]["measured_positive_roi"] is False


def test_read_reconciliation_invalidates_changed_source_decision_and_cost(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64, "criteria_met": True,
        "evidence": "Reviewed task result and sign-off.", "ai_total_cost": "25",
        "human_cost": None, "rework_cost": None, "ai_hands_on_minutes": 0,
        "review_minutes": 0, "rework_minutes": 0, "currency": "USD",
        "cost_coverage": _coverage(),
    }
    original_source = {
        "version": "a" * 64, "finished": True, "accepted": True,
        "reviewer": "user:reviewer@example.test", "status": "done",
        "runtime_cost_usd": None,
    }
    changed_source = {**original_source, "version": "b" * 64}
    monkeypatch.setattr(outcome_pilots, "get", lambda pilot_id, context: pilot)
    monkeypatch.setattr(
        outcome_pilot_sources, "resolve",
        lambda request, kind, reference: _started_source(pilot, changed_source),
    )
    with tenant_scope(tenant="workspace-one"):
        initial = bridge.sync_case(
            pilot, "1", _started_source(pilot, original_source), source_operation_id="accepted-before-drift",
            actor="user:owner@example.test", service=service,
        )
        reconciled = bridge.reconcile_record(
            object(), "workspace-context", initial["id"], service=service,
            owner_id="user:owner@example.test",
        )
        retried = bridge.reconcile_record(
            object(), "workspace-context", initial["id"], service=service,
            owner_id="user:owner@example.test",
        )

    assert initial["technical_outcome"]["status"] == "verified"
    assert initial["business_outcome"]["status"] == "accepted"
    assert reconciled["technical_outcome"]["status"] == "unresolved"
    assert reconciled["business_outcome"]["status"] == "unresolved"
    assert reconciled["costs"]["known_totals"] == {}
    assert reconciled["costs"]["complete"] is False
    assert reconciled["costs"]["events"][-1]["amount"] is None
    assert retried["revision"] == reconciled["revision"]


def test_same_source_renewal_extends_freshness_without_voiding_human_decision(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    now = [600.0]
    monkeypatch.setattr(service.store, "authoritative_time", lambda: now[0])
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64, "criteria_met": True,
        "evidence": "Reviewed task result and sign-off.", "ai_total_cost": "25",
        "human_cost": None, "rework_cost": None, "ai_hands_on_minutes": 0,
        "review_minutes": 0, "rework_minutes": 0, "currency": "USD",
        "cost_coverage": _coverage(),
    }
    source = {
        "version": "a" * 64, "finished": True, "accepted": True,
        "reviewer": "user:reviewer@example.test", "status": "done",
        "runtime_cost_usd": None,
    }
    monkeypatch.setattr(outcome_pilots, "get", lambda pilot_id, context: pilot)
    monkeypatch.setattr(
        outcome_pilot_sources, "resolve", lambda request, kind, reference: source,
    )
    with tenant_scope(tenant="workspace-one"):
        initial = bridge.sync_case(
            pilot, "1", _started_source(pilot, source), source_operation_id="accepted-before-renewal",
            actor="user:owner@example.test", service=service,
        )
        initial_decision = initial["decisions"][0]
        initial_observation = initial["observations"][0]
        now[0] = 1150.0
        renewed = bridge.reconcile_record(
            object(), "workspace-context", initial["id"], service=service,
            owner_id="user:owner@example.test",
        )

    assert renewed["evidence_version"] == initial["evidence_version"]
    assert renewed["technical_outcome"]["status"] == "verified"
    assert renewed["business_outcome"]["status"] == "accepted"
    assert renewed["decisions"][0]["id"] == initial_decision["id"]
    assert renewed["decisions"][0]["current"] is True
    assert renewed["observations"][0]["id"] == initial_observation["id"]
    assert renewed["observations"][0]["current_reason"] == "superseded"
    assert renewed["observations"][1]["valid_until"] > initial_observation["valid_until"]


def test_conflicting_source_acceptance_stays_unresolved_and_costs_finish_sync(tmp_path, monkeypatch):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64, "criteria_met": False,
        "evidence": "The frozen criterion conflicts with source acceptance.",
        "ai_total_cost": "7", "human_cost": None, "rework_cost": None,
        "ai_hands_on_minutes": 0, "review_minutes": 0, "rework_minutes": 0,
        "currency": "USD", "cost_coverage": _coverage(),
    }
    source = {
        "version": "a" * 64, "finished": True, "accepted": True,
        "reviewer": "user:reviewer@example.test", "status": "done",
        "runtime_cost_usd": 1,
    }
    with tenant_scope(tenant="workspace-one"):
        report = bridge.sync_case(
            pilot, "1", _started_source(pilot, source), source_operation_id="contradictory-source-result",
            actor="user:owner@example.test", service=service,
        )
        retried = bridge.sync_case(
            pilot, "1", _started_source(pilot, source), source_operation_id="contradictory-source-result",
            actor="user:owner@example.test", service=service,
        )
    assert report["technical_outcome"]["status"] == "failed"
    assert report["business_outcome"]["status"] == "unresolved"
    assert report["costs"]["known_totals"] == {"USD": "7"}
    assert report["costs"]["event_count"] == 5
    assert retried["revision"] == report["revision"]


def test_missing_acceptance_predicate_cannot_become_verified_or_accepted(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64, "criteria_met": None,
        "evidence": "The source finished, but the frozen criterion was not evaluated.",
        "ai_total_cost": "7", "human_cost": None, "rework_cost": None,
        "ai_hands_on_minutes": 0, "review_minutes": 0, "rework_minutes": 0,
        "currency": "USD", "cost_coverage": _coverage(),
    }
    source = {
        "version": "a" * 64, "finished": True, "accepted": True,
        "reviewer": "user:reviewer@example.test", "status": "done",
        "runtime_cost_usd": None,
    }
    with tenant_scope(tenant="workspace-one"):
        report = bridge.sync_case(
            pilot, "1", _started_source(pilot, source), source_operation_id="missing-predicate-result",
            actor="user:owner@example.test", service=service,
        )
    assert report["technical_outcome"] == {
        "status": "unresolved", "reason": "authoritative_readback_incomplete",
    }
    assert report["business_outcome"]["status"] == "unresolved"
    assert report["observations"][0]["result"] == "missing"


@pytest.mark.parametrize("accepted", [None, "false", 0])
def test_missing_or_malformed_source_acceptance_cannot_confirm_false_criterion(
    tmp_path, monkeypatch, accepted,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64, "criteria_met": False,
        "evidence": "The frozen criterion failed but authoritative acceptance is absent.",
        "ai_total_cost": "7", "human_cost": None, "rework_cost": None,
        "ai_hands_on_minutes": 0, "review_minutes": 0, "rework_minutes": 0,
        "currency": "USD", "cost_coverage": _coverage(),
    }
    source = {
        "version": "a" * 64, "finished": True,
        "reviewer": "user:reviewer@example.test", "status": "done",
        "runtime_cost_usd": None,
    }
    if accepted is not None:
        source["accepted"] = accepted
    with tenant_scope(tenant="workspace-one"):
        report = bridge.sync_case(
            pilot, "1", _started_source(pilot, source),
            source_operation_id=f"missing-source-acceptance-{type(accepted).__name__}",
            actor="user:owner@example.test", service=service,
        )
    assert report["technical_outcome"] == {
        "status": "unresolved", "reason": "authoritative_readback_incomplete",
    }
    assert report["business_outcome"]["status"] == "unresolved"
    assert report["observations"][0]["result"] == "missing"


def test_removed_cost_components_supersede_prior_values_with_unknown_tombstones(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64, "criteria_met": False, "evidence": "First evidence.",
        "ai_total_cost": None, "human_cost": "10", "rework_cost": None,
        "ai_hands_on_minutes": 10, "review_minutes": 0, "rework_minutes": 0,
        "currency": "USD", "cost_coverage": _coverage(),
    }
    source = {
        "version": "a" * 64, "finished": True, "accepted": False,
        "reviewer": "user:reviewer@example.test", "status": "failed",
        "runtime_cost_usd": 2,
    }
    with tenant_scope(tenant="workspace-one"):
        bridge.sync_case(
            pilot, "1", _started_source(pilot, source), source_operation_id="first-cost-source-version",
            actor="user:owner@example.test", service=service,
        )
        pilot["cases"][0]["measurement"].update(
            source_version="b" * 64, human_cost=None, ai_hands_on_minutes=0,
            evidence="Corrected evidence removed old prices.",
        )
        source.update(version="b" * 64, runtime_cost_usd=None)
        corrected = bridge.sync_case(
            pilot, "1", _started_source(pilot, source), source_operation_id="second-cost-source-version",
            actor="user:owner@example.test", service=service,
        )
    old_prices = [
        event for event in corrected["costs"]["events"]
        if event["amount"] in {"10", "2"}
    ]
    assert old_prices and all(event["current"] is False for event in old_prices)
    current_tombstones = [
        event for event in corrected["costs"]["events"]
        if event["current"] and event["source_version"] == "b" * 64
    ]
    assert any(event["category"] == "human" and event["amount"] is None
               for event in current_tombstones)
    assert any(event["category"] == "inference" and event["amount"] is None
               for event in current_tombstones)
    assert corrected["costs"]["known_totals"] == {}
    assert corrected["costs"]["complete"] is False


def test_failed_cost_components_share_one_attempt_identity(tmp_path, monkeypatch):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64, "criteria_met": False, "evidence": "Failed case.",
        "ai_total_cost": "25", "human_cost": "10", "rework_cost": "5",
        "ai_hands_on_minutes": 10, "review_minutes": 5, "rework_minutes": 5,
        "currency": "USD", "cost_coverage": _coverage(),
    }
    source = {
        "version": "a" * 64, "finished": True, "accepted": False,
        "reviewer": "user:reviewer@example.test", "status": "failed",
        "runtime_cost_usd": 4,
    }
    with tenant_scope(tenant="workspace-one"):
        report = bridge.sync_case(
            pilot, "1", _started_source(pilot, source), source_operation_id="one-failed-workflow-attempt",
            actor="user:owner@example.test", service=service,
        )
    assert report["costs"]["event_count"] == 5
    assert report["costs"]["failed_attempt_event_count"] == 4
    assert report["costs"]["failed_attempt_count"] == 1
    attempts = {
        event["attempt_ref"] for event in report["costs"]["events"]
        if event["aggregation"] != "coverage"
    }
    assert len(attempts) == 1


def test_read_reconciliation_repairs_crash_after_pilot_observation_commit(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64,
        "source_operation_id": "saved-pilot-observation-one",
        "criteria_met": True,
        "evidence": "Named reviewer accepted the finished source result.",
        "ai_total_cost": "12",
        "human_cost": "0",
        "rework_cost": "0",
        "ai_hands_on_minutes": 0,
        "review_minutes": 0,
        "rework_minutes": 0,
        "currency": "USD",
        "cost_coverage": _coverage(),
    }
    source = _started_source(pilot, {
        "version": "a" * 64,
        "finished": True,
        "accepted": True,
        "reviewer": "user:reviewer@example.test",
        "status": "done",
        "runtime_cost_usd": None,
    })
    monkeypatch.setattr(outcome_pilots, "get", lambda pilot_id, context: pilot)
    monkeypatch.setattr(
        outcome_pilot_sources, "resolve", lambda request, kind, reference: source,
    )
    record_id = pilot["admission_manifest"]["entries"][0]["accounting_record_id"]

    with tenant_scope(tenant="workspace-one"):
        repaired = bridge.reconcile_record(
            object(), "workspace-one", record_id, service=service,
            owner_id="user:owner@example.test",
        )
        retried = bridge.reconcile_record(
            object(), "workspace-one", record_id, service=service,
            owner_id="user:owner@example.test",
        )

    assert repaired["technical_outcome"]["status"] == "verified"
    assert repaired["business_outcome"]["status"] == "accepted"
    assert repaired["disposition"] == "completed"
    assert repaired["costs"]["known_totals"] == {"USD": "12"}
    assert retried["revision"] == repaired["revision"]


def test_read_reconciliation_invalidates_retroactive_pre_admission_start(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64,
        "source_operation_id": "retroactive-start-observation",
        "criteria_met": True,
        "evidence": "Initially valid evidence.",
        "ai_total_cost": "8",
        "human_cost": "0",
        "rework_cost": "0",
        "ai_hands_on_minutes": 0,
        "review_minutes": 0,
        "rework_minutes": 0,
        "currency": "USD",
        "cost_coverage": _coverage(),
    }
    source = _started_source(pilot, {
        "version": "a" * 64,
        "finished": True,
        "accepted": True,
        "reviewer": "user:reviewer@example.test",
        "status": "done",
        "runtime_cost_usd": None,
    })
    with tenant_scope(tenant="workspace-one"):
        initial = bridge.sync_case(
            pilot, "1", source,
            source_operation_id="retroactive-start-observation",
            actor="user:owner@example.test", service=service,
        )
    admission = pilot["admission_manifest"]["entries"][0]
    source["first_started_at"] = admission["admitted_at"]
    monkeypatch.setattr(outcome_pilots, "get", lambda pilot_id, context: pilot)
    monkeypatch.setattr(
        outcome_pilot_sources, "resolve", lambda request, kind, reference: source,
    )

    with tenant_scope(tenant="workspace-one"):
        invalidated = bridge.reconcile_record(
            object(), "workspace-one", initial["id"], service=service,
            owner_id="user:owner@example.test",
        )
        retried = bridge.reconcile_record(
            object(), "workspace-one", initial["id"], service=service,
            owner_id="user:owner@example.test",
        )

    assert invalidated["technical_outcome"]["status"] == "unresolved"
    assert invalidated["business_outcome"]["status"] == "unresolved"
    assert invalidated["costs"]["known_totals"] == {}
    assert invalidated["costs"]["complete"] is False
    assert invalidated["observations"][-1]["result"] == "unavailable"
    assert retried["revision"] == invalidated["revision"]


def test_read_reconciliation_projects_modeled_legacy_baseline_without_overwrite(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    values = OutcomeValueReporting(
        accounting=service,
        store=GovernedRecordStore(
            "test_bridge_legacy_baseline", "OBL", "outcome_value_evidence",
        ),
    )
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64,
        "source_operation_id": "legacy-baseline-observation",
        "criteria_met": True,
        "evidence": "Operator compared the prior and delivered workflow.",
        "note": "The baseline came from the pilot worksheet.",
        "baseline_cost": "30",
        "baseline_minutes": 90,
        "ai_total_cost": "10",
        "human_cost": "0",
        "rework_cost": "0",
        "ai_hands_on_minutes": 0,
        "review_minutes": 0,
        "rework_minutes": 0,
        "currency": "USD",
        "cost_coverage": _coverage(),
    }
    source = _started_source(pilot, {
        "version": "a" * 64,
        "finished": True,
        "accepted": True,
        "reviewer": "user:reviewer@example.test",
        "status": "done",
        "runtime_cost_usd": None,
    })
    monkeypatch.setattr(outcome_pilots, "get", lambda pilot_id, context: pilot)
    monkeypatch.setattr(
        outcome_pilot_sources, "resolve", lambda request, kind, reference: source,
    )
    record_id = pilot["admission_manifest"]["entries"][0]["accounting_record_id"]

    with tenant_scope(tenant="workspace-one"):
        bridge.reconcile_record(
            object(), "workspace-one", record_id, service=service,
            value_service=values, owner_id="user:owner@example.test",
        )
        first = values.case_report(record_id, owner_id="user:owner@example.test")
        bridge.reconcile_record(
            object(), "workspace-one", record_id, service=service,
            value_service=values, owner_id="user:owner@example.test",
        )
        retried = values.case_report(record_id, owner_id="user:owner@example.test")

    assert first["baseline"]["cost"] == {
        "basis": "estimated", "value": "30", "currency": "USD",
        "unknown_reason": None,
    }
    assert first["baseline"]["human_effort"]["basis"] == "estimated"
    assert first["baseline"]["human_effort"]["value"] == "90"
    assert first["comparison"]["cost"]["status"] == "modeled"
    assert retried["value_revision"] == first["value_revision"]


def test_legacy_baseline_projection_preserves_explicit_customer_evidence(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    values = OutcomeValueReporting(
        accounting=service,
        store=GovernedRecordStore(
            "test_bridge_explicit_baseline", "OBE", "outcome_value_evidence",
        ),
    )
    pilot = _pilot(service)
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64,
        "source_operation_id": "legacy-baseline-with-explicit-evidence",
        "criteria_met": True,
        "evidence": "Operator compared the prior and delivered workflow.",
        "note": "Legacy worksheet estimate.",
        "baseline_cost": "30",
        "baseline_minutes": 90,
        "ai_total_cost": "10",
        "human_cost": "0",
        "rework_cost": "0",
        "ai_hands_on_minutes": 0,
        "review_minutes": 0,
        "rework_minutes": 0,
        "currency": "USD",
        "cost_coverage": _coverage(),
    }
    source = _started_source(pilot, {
        "version": "a" * 64,
        "finished": True,
        "accepted": True,
        "reviewer": "user:reviewer@example.test",
        "status": "done",
        "runtime_cost_usd": None,
    })
    monkeypatch.setattr(outcome_pilots, "get", lambda pilot_id, context: pilot)
    monkeypatch.setattr(
        outcome_pilot_sources, "resolve", lambda request, kind, reference: source,
    )
    record_id = pilot["admission_manifest"]["entries"][0]["accounting_record_id"]

    with tenant_scope(tenant="workspace-one"):
        values.record_baseline(
            record_id,
            expected_revision=0,
            operation_id="explicit-customer-baseline",
            actor="user:owner@example.test",
            cost_basis="observed",
            cost_amount="42",
            currency="USD",
            cost_unknown_reason=None,
            human_basis="observed",
            human_minutes="75",
            human_unknown_reason=None,
            source_ref="customer-evidence:baseline-contract",
            source_version="b" * 64,
            evidence_note="Customer-approved baseline contract.",
            owner_id="user:owner@example.test",
        )
        before = values.case_report(
            record_id, owner_id="user:owner@example.test",
        )
        bridge.reconcile_record(
            object(), "workspace-one", record_id, service=service,
            value_service=values, owner_id="user:owner@example.test",
        )
        after = values.case_report(
            record_id, owner_id="user:owner@example.test",
        )

    assert after["baseline"] == before["baseline"]
    assert after["value_revision"] == before["value_revision"]
    assert after["baseline"]["source_ref"] == "customer-evidence:baseline-contract"


def test_reviewed_provider_allocation_projects_once_and_completes_declared_cost(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["provider_cost_allocations"] = {"billing-line": {"present": True}}
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64,
        "source_operation_id": "provider-allocation-observation",
        "criteria_met": True,
        "evidence": "Accepted result with separately allocated provider cost.",
        "ai_total_cost": None,
        "human_cost": "0",
        "rework_cost": "0",
        "ai_hands_on_minutes": 0,
        "review_minutes": 0,
        "rework_minutes": 0,
        "currency": "USD",
        "cost_coverage": _coverage(
            "provider_usage", "review", "rework", "allocation",
        ),
    }
    source = _started_source(pilot, {
        "version": "a" * 64,
        "finished": True,
        "accepted": True,
        "reviewer": "user:reviewer@example.test",
        "status": "done",
        "runtime_cost_usd": None,
    })
    allocation = {
        "status": "current",
        "evidence_class": "admitted_provider_cost_with_operator_allocation",
        "provider_invoice_verified": False,
        "allocations": [],
        "current_totals_by_currency": {"USD": "40"},
        "current_case_totals": {"1": {"USD": "40"}},
        "coverage": {"version": "c" * 64},
    }
    monkeypatch.setattr(outcome_pilots, "get", lambda pilot_id, context: pilot)
    monkeypatch.setattr(
        outcome_pilot_sources, "resolve", lambda request, kind, reference: source,
    )
    monkeypatch.setattr(outcome_pilot_costs, "report", lambda *args, **kwargs: allocation)
    record_id = pilot["admission_manifest"]["entries"][0]["accounting_record_id"]

    with tenant_scope(tenant="workspace-one"):
        projected = bridge.reconcile_record(
            object(), "workspace-one", record_id, service=service,
            owner_id="user:owner@example.test",
        )
        retried = bridge.reconcile_record(
            object(), "workspace-one", record_id, service=service,
            owner_id="user:owner@example.test",
        )

    allocation_event = next(
        row for row in projected["costs"]["events"]
        if row["current"] and ":provider-allocation:" in row["source_ref"]
    )
    assert projected["costs"]["known_totals"] == {"USD": "40"}
    assert projected["costs"]["complete"] is True
    assert allocation_event["aggregation"] == "additive"
    assert allocation_event["source_assurance"] == "application_observation"
    assert "not independently verified" in allocation_event["evidence_note"]
    assert retried["revision"] == projected["revision"]

    # A separate additive provider line makes the reviewed allocation detail
    # informational. Its still-declared allocation family must remain incomplete
    # instead of reaching the core with an impossible completeness assertion.
    with tenant_scope(tenant="workspace-one"):
        raw = service.store.get(record_id)
        raw = service.record_cost(
            raw["id"], expected_revision=raw["revision"],
            operation_id="settled-receipt-seed-one", actor="system:receipt",
            category="inference", attempt_state="succeeded", basis="observed",
            amount="8", currency="USD", source_ref="receipt:one",
            source_version="9" * 64, source_assurance="application_observation",
        )
        source.update(
            provider_cost_receipts=[{
                "reference": "receipt:one",
                "state": "settled",
                "operation": {
                    "operation_id": "provider-operation:receipt-one",
                    "category": "inference",
                    "parent_category": "inference",
                    "attempt_no": 1,
                    "service": "provider",
                    "attempt_state": "succeeded",
                },
            }],
            provider_cost_receipts_complete=True,
            provider_cost_receipts_catalog_version="8" * 64,
        )
        allocation.update(
            current_totals_by_currency={"USD": "10"},
            current_case_totals={"1": {"USD": "10"}},
            coverage={"version": "d" * 64},
        )
        raw = bridge._sync_reviewed_provider_allocations(
            service, raw, pilot, "1", source, pilot["cases"][0]["measurement"],
            resolve=lambda *_: source,
        )
        receipt_backed = service.report(raw["id"])

    assert receipt_backed["costs"]["known_totals"] == {"USD": "8"}
    assert receipt_backed["costs"]["complete"] is False
    assert next(
        row for row in receipt_backed["costs"]["events"]
        if row["current"] and ":provider-allocation:" in row["source_ref"]
    )["aggregation"] == "informational"


def test_reviewed_provider_allocation_is_informational_beside_all_in_total(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["provider_cost_allocations"] = {"billing-line": {"present": True}}
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64,
        "source_operation_id": "all-in-allocation-observation",
        "criteria_met": True,
        "evidence": "All-in total includes the provider allocation detail.",
        "ai_total_cost": "10",
        "human_cost": "3",
        "rework_cost": "0",
        "ai_hands_on_minutes": 4,
        "review_minutes": 1,
        "rework_minutes": 0,
        "currency": "USD",
        "cost_coverage": _coverage(),
    }
    source = _started_source(pilot, {
        "version": "a" * 64,
        "finished": True,
        "accepted": True,
        "reviewer": "user:reviewer@example.test",
        "status": "done",
        "runtime_cost_usd": None,
    })
    allocation = {
        "status": "current",
        "evidence_class": "admitted_provider_cost_with_operator_allocation",
        "provider_invoice_verified": False,
        "allocations": [],
        "current_totals_by_currency": {"USD": "6"},
        "current_case_totals": {"1": {"USD": "6"}},
        "coverage": {"version": "d" * 64},
    }
    monkeypatch.setattr(outcome_pilots, "get", lambda pilot_id, context: pilot)
    monkeypatch.setattr(
        outcome_pilot_sources, "resolve", lambda request, kind, reference: source,
    )
    monkeypatch.setattr(outcome_pilot_costs, "report", lambda *args, **kwargs: allocation)
    record_id = pilot["admission_manifest"]["entries"][0]["accounting_record_id"]

    with tenant_scope(tenant="workspace-one"):
        projected = bridge.reconcile_record(
            object(), "workspace-one", record_id, service=service,
            owner_id="user:owner@example.test",
        )

    allocation_event = next(
        row for row in projected["costs"]["events"]
        if row["current"] and ":provider-allocation:" in row["source_ref"]
    )
    assert projected["costs"]["known_totals"] == {"USD": "10"}
    assert allocation_event["amount"] == "6"
    assert allocation_event["aggregation"] == "informational"


def test_removed_provider_allocation_retires_its_projected_cost(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["provider_cost_allocations"] = {"billing-line": {"present": True}}
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64,
        "source_operation_id": "allocation-removal-observation",
        "criteria_met": True,
        "evidence": "Accepted result with a reviewed provider allocation.",
        "ai_total_cost": None,
        "human_cost": "0",
        "rework_cost": "0",
        "ai_hands_on_minutes": 0,
        "review_minutes": 0,
        "rework_minutes": 0,
        "currency": "USD",
        "cost_coverage": _coverage(
            "provider_usage", "review", "rework", "allocation",
        ),
    }
    source = _started_source(pilot, {
        "version": "a" * 64,
        "finished": True,
        "accepted": True,
        "reviewer": "user:reviewer@example.test",
        "status": "done",
        "runtime_cost_usd": None,
    })
    allocation = {
        "status": "current",
        "evidence_class": "admitted_provider_cost_with_operator_allocation",
        "provider_invoice_verified": False,
        "allocations": [],
        "current_totals_by_currency": {"USD": "40"},
        "current_case_totals": {"1": {"USD": "40"}},
        "coverage": {"version": "e" * 64},
    }
    monkeypatch.setattr(outcome_pilots, "get", lambda pilot_id, context: pilot)
    monkeypatch.setattr(
        outcome_pilot_sources, "resolve", lambda request, kind, reference: source,
    )
    monkeypatch.setattr(
        outcome_pilot_costs, "report", lambda *args, **kwargs: allocation,
    )
    record_id = pilot["admission_manifest"]["entries"][0]["accounting_record_id"]

    with tenant_scope(tenant="workspace-one"):
        first = bridge.reconcile_record(
            object(), "workspace-one", record_id, service=service,
            owner_id="user:owner@example.test",
        )
        pilot["provider_cost_allocations"] = {}
        allocation["current_totals_by_currency"] = {}
        allocation["current_case_totals"] = {}
        allocation["coverage"] = {"version": "f" * 64}
        retired = bridge.reconcile_record(
            object(), "workspace-one", record_id, service=service,
            owner_id="user:owner@example.test",
        )

    first_row = next(
        row for row in first["costs"]["events"]
        if row["current"] and ":provider-allocation:" in row["source_ref"]
    )
    current_rows = [
        row for row in retired["costs"]["events"]
        if row["current"] and ":provider-allocation:" in row["source_ref"]
    ]
    assert first_row["amount"] == "40"
    assert len(current_rows) == 1
    assert current_rows[0]["amount"] is None
    assert current_rows[0]["attempt_state"] == "unknown"
    assert retired["costs"]["complete"] is False


def test_partial_allocation_keeps_current_known_lower_bound(tmp_path, monkeypatch):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["provider_cost_allocations"] = {"billing-line": {"present": True}}
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64,
        "source_operation_id": "partial-allocation-observation",
        "criteria_met": True,
        "evidence": "Reviewed provider allocation.",
        "ai_total_cost": None,
        "human_cost": "0",
        "rework_cost": "0",
        "ai_hands_on_minutes": 0,
        "review_minutes": 0,
        "rework_minutes": 0,
        "currency": "USD",
        "cost_coverage": _coverage(
            "provider_usage", "review", "rework", "allocation",
        ),
    }
    source = _started_source(pilot, {
        "version": "a" * 64,
        "finished": True,
        "accepted": True,
        "reviewer": "user:reviewer@example.test",
        "status": "done",
        "runtime_cost_usd": None,
    })
    projection = {
        "status": "current",
        "evidence_class": "admitted_provider_cost_with_operator_allocation",
        "provider_invoice_verified": False,
        "allocations": [],
        "current_totals_by_currency": {"USD": "15"},
        "current_case_totals": {"1": {"USD": "15"}},
        "coverage": {"version": "c" * 64},
    }
    monkeypatch.setattr(outcome_pilots, "get", lambda *_: pilot)
    monkeypatch.setattr(outcome_pilot_sources, "resolve", lambda *_: source)
    monkeypatch.setattr(outcome_pilot_costs, "report", lambda *args, **kwargs: projection)
    record_id = pilot["admission_manifest"]["entries"][0]["accounting_record_id"]

    with tenant_scope(tenant="workspace-one"):
        first = bridge.reconcile_record(
            object(), "workspace-one", record_id, service=service,
            owner_id="user:owner@example.test",
        )
        projection.update(
            status="partial",
            current_totals_by_currency={"USD": "10"},
            current_case_totals={"1": {"USD": "10"}},
            coverage={"version": "d" * 64},
        )
        second = bridge.reconcile_record(
            object(), "workspace-one", record_id, service=service,
            owner_id="user:owner@example.test",
        )

    assert first["costs"]["known_totals"] == {"USD": "15"}
    assert second["costs"]["known_totals"] == {"USD": "10"}
    assert second["costs"]["complete"] is False
    assert any(
        row["current"]
        and row["source_ref"].endswith("unavailable-remainder")
        and row["amount"] is None
        for row in second["costs"]["events"]
    )


def test_existing_bridge_operation_repairs_a_competing_current_projection(
    tmp_path, monkeypatch,
):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    record_id = pilot["admission_manifest"]["entries"][0]["accounting_record_id"]
    source_ref = "outcome-pilot:OPL-test:1:runtime"
    operation_id = "bridge-owned-projection-one"
    with tenant_scope(tenant="workspace-one"):
        raw = service.store.get(record_id)
        raw = bridge._cost(
            service,
            raw,
            operation_id=operation_id,
            actor="system:source",
            category="inference",
            amount="8",
            currency="USD",
            source_ref=source_ref,
            source_version="a" * 64,
            attempt_state="succeeded",
            basis="observed",
        )
        initial = raw["cost_events"][-1]
        raw = service.record_cost(
            raw["id"], expected_revision=raw["revision"],
            operation_id="competing-source-projection-one", actor="system:source",
            category="inference", attempt_state="succeeded", basis="observed",
            amount="0", currency="USD", source_ref=source_ref,
            source_version="b" * 64, source_assurance="application_observation",
            correction_of=initial["id"], correction_reason="A stale competing projection.",
        )
        repaired = bridge._cost(
            service,
            raw,
            operation_id=operation_id,
            actor="system:source",
            category="inference",
            amount="8",
            currency="USD",
            source_ref=source_ref,
            source_version="a" * 64,
            attempt_state="succeeded",
            basis="observed",
        )
        retried = bridge._cost(
            service,
            repaired,
            operation_id=operation_id,
            actor="system:source",
            category="inference",
            amount="8",
            currency="USD",
            source_ref=source_ref,
            source_version="a" * 64,
            attempt_state="succeeded",
            basis="observed",
        )
        report = service.report(record_id)

    assert report["costs"]["known_totals"] == {"USD": "8"}
    assert retried["revision"] == repaired["revision"]
    assert sum(row["current"] for row in report["costs"]["events"]) == 1


def test_negative_provider_allocation_is_explicitly_unavailable(tmp_path, monkeypatch):
    service = _service(tmp_path, monkeypatch)
    pilot = _pilot(service)
    pilot["provider_cost_allocations"] = {"billing-line": {"present": True}}
    pilot["cases"][0]["measurement"] = {
        "source_version": "a" * 64,
        "source_operation_id": "negative-allocation-observation",
        "criteria_met": True,
        "evidence": "Reviewed provider allocation includes a credit.",
        "ai_total_cost": None,
        "human_cost": "0",
        "rework_cost": "0",
        "ai_hands_on_minutes": 0,
        "review_minutes": 0,
        "rework_minutes": 0,
        "currency": "USD",
        "cost_coverage": _coverage(
            "provider_usage", "review", "rework", "allocation",
        ),
    }
    source = _started_source(pilot, {
        "version": "a" * 64,
        "finished": True,
        "accepted": True,
        "reviewer": "user:reviewer@example.test",
        "status": "done",
        "runtime_cost_usd": None,
    })
    projection = {
        "status": "current",
        "evidence_class": "admitted_provider_cost_with_operator_allocation",
        "provider_invoice_verified": False,
        "allocations": [],
        "current_totals_by_currency": {"USD": "-5"},
        "current_case_totals": {"1": {"USD": "-5"}},
        "coverage": {"version": "e" * 64},
    }
    monkeypatch.setattr(outcome_pilots, "get", lambda *_: pilot)
    monkeypatch.setattr(outcome_pilot_sources, "resolve", lambda *_: source)
    monkeypatch.setattr(outcome_pilot_costs, "report", lambda *args, **kwargs: projection)
    record_id = pilot["admission_manifest"]["entries"][0]["accounting_record_id"]

    with tenant_scope(tenant="workspace-one"):
        report = bridge.reconcile_record(
            object(), "workspace-one", record_id, service=service,
            owner_id="user:owner@example.test",
        )

    assert report["costs"]["complete"] is False
    assert all(not amount.startswith("-") for amount in report["costs"]["known_totals"].values())
    assert any(
        row["current"]
        and "negative net credit" in (row.get("unknown_reason") or "")
        for row in report["costs"]["events"]
    )
