from __future__ import annotations

from decimal import Decimal

import pytest
from maverick import outcome_value_reporting as value_module
from maverick.governed_records import GovernedRecordStore
from maverick.outcome_accounting import COST_COVERAGE_FAMILIES, OutcomeAccounting
from maverick.outcome_value_reporting import OutcomeValueReporting
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict


@pytest.fixture
def services(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    accounting = OutcomeAccounting(store=GovernedRecordStore(
        "test_outcome_value_accounting", "OVA", "outcome_accounting",
    ))
    values = OutcomeValueReporting(
        accounting=accounting,
        store=GovernedRecordStore(
            "test_outcome_value_evidence", "OVE", "outcome_value_evidence",
        ),
    )
    with tenant_scope(tenant="customer-one"):
        yield accounting, values


def _admit(accounting, suffix):
    return accounting.admit(
        admission_id=f"pilot-one:case-{suffix}",
        work_item_id=f"goal:{suffix}",
        acceptance_contract_ref="outcome-pilot:pilot-one:plan-v1",
        owner_id="user:alice",
        actor="user:alice",
    )


def _coverage(*included):
    selected = set(included)
    return {
        family: {
            "status": "included" if family in selected or "all" in selected else "zero",
            "note": (
                "Included in the complete delivered-cost evidence."
                if family in selected or "all" in selected else
                "Reviewed evidence confirms zero for this cost family."
            ),
        }
        for family in COST_COVERAGE_FAMILIES
    }


def _complete_cost(accounting, record, amount, *, operation, category="other", **changes):
    coverage = changes.pop("coverage", "complete")
    return accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id=operation, actor="user:alice", category=category,
        attempt_state=changes.pop("attempt_state", "succeeded"),
        basis=changes.pop("basis", "observed"), amount=amount,
        currency="USD" if amount is not None else None,
        source_ref=changes.pop("source_ref", operation), source_version="a" * 64,
        coverage=coverage,
        coverage_declarations=changes.pop(
            "coverage_declarations", _coverage("all") if coverage == "complete" else None,
        ),
        all_in_total=changes.pop("all_in_total", True),
        **changes,
    )


def _baseline(values, record, *, cost="10", cost_basis="observed", human="60",
              human_basis="observed", operation="baseline-evidence-one"):
    return values.record_baseline(
        record["id"], expected_revision=0, operation_id=operation,
        actor="user:alice", cost_basis=cost_basis, cost_amount=cost,
        currency="USD" if cost is not None else None,
        cost_unknown_reason=None if cost is not None else "No baseline invoice was supplied.",
        human_basis=human_basis, human_minutes=human,
        human_unknown_reason=None if human is not None else "No baseline time record was supplied.",
        source_ref=f"baseline:{record['id']}", source_version="b" * 64,
        evidence_note="Operator supplied baseline evidence for this admitted case.",
    )


def test_decimal_zero_with_hostile_exponent_is_normalized_before_rendering(services):
    accounting, values = services
    record = _admit(accounting, "zero-exponent")
    baseline = values.record_baseline(
        record["id"], expected_revision=0,
        operation_id="zero-exponent-baseline", actor="user:alice",
        cost_basis="observed", cost_amount=Decimal("0e-999999999"),
        currency="USD", cost_unknown_reason=None,
        human_basis="observed", human_minutes=Decimal("0e-999999999"),
        human_unknown_reason=None, source_ref="baseline:zero-exponent",
        source_version="b" * 64,
        evidence_note="A zero remains zero regardless of its Decimal exponent.",
    )
    commercial = values.record_commercial(
        record["id"], expected_revision=baseline["revision"],
        operation_id="zero-exponent-commercial", actor="user:alice",
        kind="renewal", stage="observed", basis="observed",
        amount=Decimal("0e-999999999"), currency="USD",
        unknown_reason=None, source_ref="crm:zero-exponent",
        source_version="c" * 64, note="A zero-value observed renewal.",
    )

    report = values.case_report(record["id"], owner_id="user:alice")
    assert commercial["revision"] == 3
    assert report["baseline"]["cost"]["value"] == "0"
    assert report["baseline"]["human_effort"]["value"] == "0"
    assert report["renewals"][-1]["amount"]["value"] == "0"


def test_complete_cohort_keeps_every_admission_and_reconciles_manual_totals(services):
    accounting, values = services
    records = [_admit(accounting, str(index)) for index in range(4)]

    observed = accounting.record_observation(
        records[0]["id"], expected_revision=records[0]["revision"],
        operation_id="accepted-readback-one", actor="user:alice",
        source_id="task:accepted", source_version="c" * 64,
        result="confirmed", authoritative=True, summary="Readback matched.",
    )
    records[0] = accounting.record_decision(
        observed["id"], expected_revision=observed["revision"],
        operation_id="accepted-human-review", actor="user:reviewer",
        decision="accepted", rationale="Reviewed against the frozen contract.",
        evidence_version=accounting.report(observed["id"])["evidence_version"],
    )
    records[1] = accounting.record_disposition(
        records[1]["id"], expected_revision=records[1]["revision"],
        operation_id="failed-case-lifecycle", actor="user:alice",
        disposition="failed", reason="The admitted workflow failed.",
    )
    records[2] = accounting.record_disposition(
        records[2]["id"], expected_revision=records[2]["revision"],
        operation_id="cancelled-case-lifecycle", actor="user:alice",
        disposition="cancelled", reason="The customer cancelled the admitted workflow.",
    )

    delivered = [Decimal("4"), Decimal("3"), Decimal("2"), Decimal("1")]
    for index, record in enumerate(records):
        if index == 1:
            request = dict(
                record_id=record["id"], expected_revision=record["revision"],
                operation_id="failed-retry-cost-one", actor="user:alice",
                category="retry", attempt_state="failed", basis="observed",
                amount="3", currency="USD", source_ref="retry:failed:one",
                    source_version="d" * 64, coverage="complete",
                    coverage_declarations=_coverage("failed_attempts"),
                attempt_ref="attempt:retry-one",
            )
            saved = accounting.record_cost(**request)
            assert accounting.record_cost(**request)["revision"] == saved["revision"]
            records[index] = saved
        else:
            records[index] = _complete_cost(
                accounting, record, str(delivered[index]),
                operation=f"delivered-cost-case-{index}",
            )
        # Human minutes are an observed cost dimension and remain separate from money.
        records[index] = accounting.record_cost(
            records[index]["id"], expected_revision=records[index]["revision"],
            operation_id=f"human-effort-case-{index}", actor="user:alice",
            category="review", attempt_state="succeeded", basis="observed",
            amount="0", currency="USD", quantity="10", unit="minutes",
            source_ref=f"timesheet:case-{index}", source_version="e" * 64,
                coverage="complete",
                coverage_declarations=_coverage(
                    "review",
                    *(("failed_attempts",) if index == 1 else ()),
                ),
        )
        _baseline(values, records[index], operation=f"baseline-evidence-case-{index}")

    cohort = values.cohort_report(owner_id="user:alice")
    export = values.export_report(owner_id="user:alice")
    assert cohort["admitted"] == 4
    assert cohort["categories"] == {
        "accepted": 1, "cancelled": 1, "failed": 1, "rejected": 0, "unresolved": 1,
    }
    assert cohort["reconciles"] is True
    assert cohort["costs"]["known_totals"] == {"USD": "10"}
    assert cohort["costs"]["category_totals"] == {
        "other": {"USD": "7"},
        "retry": {"USD": "3"},
        "review": {"USD": "0"},
    }
    assert cohort["costs"]["failed_attempts"] == 1
    assert cohort["comparison"]["cost"] == {
        "status": "measured", "missing_records": [], "currency": "USD",
        "baseline_total": "40", "delivered_total": "10", "net_savings": "30",
        "roi_percent": "75", "measured_positive_roi": True,
    }
    assert cohort["comparison"]["human_effort"]["minutes_saved"] == "200"
    assert export["admitted"] == cohort["admitted"]
    assert export["cohort_sha256"]
    assert all(case["timestamps"]["admitted_at"] for case in export["cases"])


def test_missing_evidence_withholds_roi_and_estimates_remain_modeled(services):
    accounting, values = services
    missing = _complete_cost(
        accounting, _admit(accounting, "missing"), "2",
        operation="complete-delivered-missing-baseline",
    )
    values.record_baseline(
        missing["id"], expected_revision=0, operation_id="missing-baseline-components",
        actor="user:alice", cost_basis="unknown", cost_amount=None, currency=None,
        cost_unknown_reason="Provider baseline evidence is unavailable.",
        human_basis="unknown", human_minutes=None,
        human_unknown_reason="Human-time baseline evidence is unavailable.",
        source_ref="baseline:missing", source_version="f" * 64,
        evidence_note="The operator documented both missing components.",
    )
    estimated = _complete_cost(
        accounting, _admit(accounting, "estimated"), "4",
        operation="estimated-delivered-cost", basis="estimated",
    )
    estimated = accounting.record_cost(
        estimated["id"], expected_revision=estimated["revision"],
        operation_id="estimated-delivered-human-time", actor="user:alice",
        category="review", attempt_state="succeeded", basis="estimated",
        amount="0", currency="USD", quantity="5", unit="minutes",
        source_ref="timesheet:estimated", source_version="a" * 64,
        coverage="complete", coverage_declarations=_coverage("all"),
    )
    _baseline(
        values, estimated, cost="10", cost_basis="estimated", human="20",
        human_basis="estimated", operation="estimated-baseline-evidence",
    )

    missing_case = values.case_report(missing["id"], owner_id="user:alice")
    estimated_case = values.case_report(estimated["id"], owner_id="user:alice")
    cohort = values.cohort_report(owner_id="user:alice")
    assert missing_case["comparison"]["cost"]["status"] == "unavailable"
    assert missing_case["comparison"]["cost"]["net_savings"] is None
    assert missing_case["comparison"]["cost"]["reason"] == (
        "baseline cost evidence is incomplete"
    )
    assert missing_case["comparison"]["measured_positive_roi"] is False
    assert estimated_case["comparison"]["cost"]["status"] == "modeled"
    assert estimated_case["comparison"]["cost"]["net_savings"] == "6"
    assert estimated_case["comparison"]["measured_positive_roi"] is False
    assert cohort["comparison"]["cost"]["status"] == "unavailable"
    assert cohort["comparison"]["cost"]["net_savings"] is None
    assert cohort["comparison"]["cost"]["roi_percent"] is None


def test_missing_delivered_human_time_withholds_positive_measured_roi(services):
    accounting, values = services
    record = _complete_cost(
        accounting, _admit(accounting, "missing-delivered-human"), "3",
        operation="complete-monetary-cost-without-human-time",
    )
    _baseline(
        values, record, cost="10", cost_basis="observed", human="60",
        human_basis="observed", operation="observed-baseline-with-human-time",
    )

    case = values.case_report(record["id"], owner_id="user:alice")
    assert case["outcome"]["costs"]["complete"] is True
    assert case["comparison"]["human_effort"]["status"] == "unavailable"
    assert "delivered_human_time" in case["comparison"]["missing_components"]
    assert case["comparison"]["cost"]["status"] == "unavailable"
    assert case["comparison"]["cost"]["net_savings"] is None
    assert case["comparison"]["cost"]["roi_percent"] is None
    assert case["comparison"]["measured_positive_roi"] is False


def test_missing_quantity_on_one_support_component_withholds_measured_roi(services):
    accounting, values = services
    record = _complete_cost(
        accounting, _admit(accounting, "partial-delivered-human"), "3",
        operation="all-in-cost-with-partial-human-time",
    )
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="review-time-present", actor="user:alice",
        category="review", attempt_state="succeeded", basis="observed",
        amount="0", currency="USD", quantity="10", unit="minutes",
        source_ref="timesheet:review-present", source_version="a" * 64,
        aggregation="informational",
    )
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="support-time-missing", actor="user:alice",
        category="support", attempt_state="succeeded", basis="observed",
        amount="0", currency="USD", quantity=None, unit=None,
        source_ref="timesheet:support-missing", source_version="b" * 64,
        aggregation="informational",
    )
    _baseline(
        values, record, cost="10", cost_basis="observed", human="60",
        human_basis="observed", operation="baseline-for-partial-human-time",
    )

    case = values.case_report(record["id"], owner_id="user:alice")
    assert case["outcome"]["costs"]["complete"] is True
    assert case["comparison"]["human_effort"] == {
        "status": "unavailable",
        "baseline": case["baseline"]["human_effort"],
        "delivered": {
            "status": "unknown",
            "minutes": None,
            "basis": "unknown",
            "reason": "one or more delivered human-time components are missing",
        },
        "minutes_saved": None,
    }
    assert "delivered_human_time" in case["comparison"]["missing_components"]
    assert case["comparison"]["cost"]["status"] == "unavailable"
    assert case["comparison"]["cost"]["net_savings"] is None
    assert case["comparison"]["measured_positive_roi"] is False


def test_modeled_human_time_cannot_label_aggregate_roi_as_measured_positive(services):
    accounting, values = services
    record = _complete_cost(
        accounting, _admit(accounting, "modeled-delivered-human"), "3",
        operation="observed-monetary-cost-with-modeled-human-time",
    )
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="modeled-human-time-component", actor="user:alice",
        category="review", attempt_state="succeeded", basis="estimated",
        amount="0", currency="USD", quantity="15", unit="minutes",
        source_ref="timesheet:modeled-human", source_version="b" * 64,
        aggregation="informational",
    )
    _baseline(
        values, record, cost="10", cost_basis="observed", human="60",
        human_basis="observed", operation="observed-baseline-modeled-human",
    )

    case = values.case_report(record["id"], owner_id="user:alice")
    cohort = values.cohort_report(owner_id="user:alice")
    assert case["comparison"]["cost"]["status"] == "measured"
    assert case["comparison"]["human_effort"]["status"] == "modeled"
    assert case["comparison"]["measured_positive_roi"] is False
    assert cohort["comparison"]["cost"]["status"] == "measured"
    assert cohort["comparison"]["cost"]["measured_positive_roi"] is False
    assert cohort["comparison"]["human_effort"]["status"] == "modeled"


def test_exact_manifest_keeps_same_owner_pilots_isolated(services):
    accounting, values = services
    plan_one, plan_two = "1" * 64, "2" * 64
    pilot_one, pilot_two = "OPL-isolated-one", "OPL-isolated-two"
    first = accounting.admit(
        admission_id=f"{pilot_one}:case-one", work_item_id="goal:first-pilot-only",
        acceptance_contract_ref=f"outcome-pilot:{pilot_one}:{plan_one}",
        owner_id="user:alice", actor="user:alice",
    )
    second = accounting.admit(
        admission_id=f"{pilot_two}:case-one", work_item_id="goal:second-pilot-only",
        acceptance_contract_ref=f"outcome-pilot:{pilot_two}:{plan_two}",
        owner_id="user:alice", actor="user:alice",
    )

    first_report = values.cohort_report(
        owner_id="user:alice", record_ids=[first["id"]],
        acceptance_contract_ref=f"outcome-pilot:{pilot_one}:{plan_one}",
    )
    second_report = values.export_report(
        owner_id="user:alice", record_ids=[second["id"]],
        acceptance_contract_ref=f"outcome-pilot:{pilot_two}:{plan_two}",
    )
    assert [row["outcome"]["id"] for row in first_report["cases"]] == [first["id"]]
    assert [row["outcome"]["id"] for row in second_report["cases"]] == [second["id"]]
    assert first_report["cohort_binding"]["acceptance_contract_ref"] == (
        f"outcome-pilot:{pilot_one}:{plan_one}"
    )
    assert first_report["cohort_binding"]["record_count"] == 1
    assert len(first_report["cohort_binding"]["record_ids_sha256"]) == 64
    assert first_report["cohort_binding"]["record_ids_sha256"] != (
        second_report["cohort_binding"]["record_ids_sha256"]
    )
    with pytest.raises(RecordConflict, match="no longer matches its contract"):
        values.cohort_report(
            owner_id="user:alice", record_ids=[first["id"], second["id"]],
            acceptance_contract_ref=f"outcome-pilot:{pilot_one}:{plan_one}",
        )


def test_fractional_cohort_and_category_totals_do_not_round_at_28_digits(services):
    accounting, values = services
    _complete_cost(
        accounting, _admit(accounting, "fractional-cohort-one"),
        "1000000000000000000.000000000001",
        operation="fractional-cohort-large-total",
    )
    _complete_cost(
        accounting, _admit(accounting, "fractional-cohort-two"),
        "0.000000000001",
        operation="fractional-cohort-small-total",
    )

    cohort = values.cohort_report(owner_id="user:alice")
    expected = "1000000000000000000.000000000002"
    assert cohort["costs"]["known_totals"] == {"USD": expected}
    assert cohort["costs"]["category_totals"] == {
        "other": {"USD": expected},
    }


def test_extreme_valid_ratio_is_reported_as_unavailable_overflow(services):
    accounting, values = services
    record = _complete_cost(
        accounting,
        _admit(accounting, "ratio-overflow"),
        "999999999999999999",
        operation="ratio-overflow-delivered-cost",
    )
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="ratio-overflow-human-time", actor="user:alice",
        category="review", attempt_state="succeeded", basis="observed",
        amount="0", currency="USD", quantity="1", unit="minutes",
        source_ref="timesheet:ratio-overflow", source_version="c" * 64,
        coverage="complete", coverage_declarations=_coverage("all"),
    )
    _baseline(
        values,
        record,
        cost="0.000000000000000001",
        human="2",
        operation="ratio-overflow-baseline",
    )

    case = values.case_report(record["id"], owner_id="user:alice")
    cohort = values.cohort_report(owner_id="user:alice")

    assert case["comparison"]["cost"] == {
        "status": "unavailable",
        "baseline": case["baseline"]["cost"],
        "delivered": {
            "amount": "999999999999999999",
            "currency": "USD",
            "basis": "observed",
        },
        "net_savings": None,
        "roi_percent": None,
        "overflow": True,
        "reason": "the cost comparison exceeds the reporting bound",
    }
    assert "cost_comparison_overflow" in case["comparison"]["missing_components"]
    assert case["comparison"]["measured_positive_roi"] is False
    assert cohort["comparison"]["cost"]["status"] == "unavailable"
    assert cohort["comparison"]["cost"]["overflow"] is True
    assert cohort["comparison"]["cost"]["net_savings"] is None
    assert cohort["comparison"]["cost"]["roi_percent"] is None


def test_cost_dedup_correction_allocation_and_commercial_records_are_auditable(services):
    accounting, values = services
    record = _admit(accounting, "correction")
    request = dict(
        record_id=record["id"], expected_revision=record["revision"],
        operation_id="allocated-support-cost", actor="user:alice",
        category="support", attempt_state="succeeded", basis="observed",
        amount="2", currency="USD", source_ref="support:shared-line",
        quantity="30", unit="minutes",
        source_version="a" * 64, coverage="complete",
        coverage_declarations=_coverage("support", "allocation"),
        allocation_method="usage_weighted",
        allocation_assumption="Allocated from the shared support line by admitted case minutes.",
    )
    first = accounting.record_cost(**request)
    duplicate = accounting.record_cost(**request)
    assert duplicate["revision"] == first["revision"]
    original = accounting.report(record["id"])["costs"]["events"][0]
    corrected = accounting.record_cost(
        record["id"], expected_revision=first["revision"],
        operation_id="corrected-support-cost", actor="user:alice",
        category="support", attempt_state="succeeded", basis="observed",
        amount="3", currency="USD", source_ref="support:shared-line",
        quantity="30", unit="minutes",
        source_version="b" * 64, coverage="complete",
        coverage_declarations=_coverage("support", "allocation"),
        allocation_method="usage_weighted",
        allocation_assumption="Recalculated from corrected admitted case minutes.",
        correction_of=original["id"],
        correction_reason="The first source line omitted one reviewed support hour.",
    )
    report = accounting.report(record["id"])
    assert report["costs"]["known_totals"] == {"USD": "3"}
    assert report["costs"]["superseded_event_count"] == 1
    assert report["costs"]["events"][0]["current"] is False
    assert report["costs"]["events"][1]["correction_reason"].startswith("The first")
    assert report["costs"]["events"][1]["allocation_method"] == "usage_weighted"

    baseline = _baseline(values, corrected, operation="baseline-for-commercial")
    renewal = values.record_commercial(
        corrected["id"], expected_revision=baseline["revision"],
        operation_id="renewal-record-one", actor="user:alice",
        kind="renewal", stage="proposed", basis="estimated", amount="100",
        currency="USD", unknown_reason=None, source_ref="crm:renewal-one",
        source_version="c" * 64, note="Renewal proposal recorded separately.",
    )
    values.record_commercial(
        corrected["id"], expected_revision=renewal["revision"],
        operation_id="expansion-record-one", actor="user:alice",
        kind="expansion", stage="won", basis="observed", amount="25",
        currency="USD", unknown_reason=None, source_ref="crm:expansion-one",
        source_version="d" * 64, note="Expansion order recorded separately.",
    )
    cohort = values.cohort_report(owner_id="user:alice")
    assert len(cohort["commercial"]["renewals"]) == 1
    assert len(cohort["commercial"]["expansions"]) == 1
    assert cohort["commercial_separate_from_savings"] is True
    assert cohort["comparison"]["commercial_records_included"] is False
    assert cohort["comparison"]["cost"]["delivered_total"] == "3"


def test_baseline_replacement_requires_current_target_and_documented_reason(services):
    accounting, values = services
    record = _admit(accounting, "baseline-correction")
    first = _baseline(values, record, operation="first-baseline-record")
    assert _baseline(
        values, record, operation="first-baseline-record",
    )["revision"] == first["revision"]
    current = values.case_report(record["id"])["baseline"]
    with pytest.raises(RecordConflict, match="documented correction"):
        _baseline(values, record, operation="unlinked-baseline-record")
    with pytest.raises(ValueError, match="requires its reason"):
        values.record_baseline(
            record["id"], expected_revision=first["revision"],
            operation_id="undocumented-baseline-change", actor="user:alice",
            cost_basis="observed", cost_amount="12", currency="USD",
            cost_unknown_reason=None, human_basis="observed", human_minutes="60",
            human_unknown_reason=None, source_ref=f"baseline:{record['id']}",
            source_version="c" * 64, evidence_note="Corrected baseline source.",
            correction_of=current["id"],
        )
    saved = values.record_baseline(
        record["id"], expected_revision=first["revision"],
        operation_id="documented-baseline-change", actor="user:alice",
        cost_basis="observed", cost_amount="12", currency="USD",
        cost_unknown_reason=None, human_basis="observed", human_minutes="60",
        human_unknown_reason=None, source_ref=f"baseline:{record['id']}",
        source_version="c" * 64, evidence_note="Corrected baseline source.",
        correction_of=current["id"], correction_reason="Corrected source total.",
    )
    case = values.case_report(record["id"])
    assert saved["revision"] == 3
    assert case["baseline"]["cost"]["value"] == "12"
    assert [row["current"] for row in case["baseline_history"]] == [False, True]


def test_commercial_exact_retry_is_idempotent_and_same_source_change_needs_correction(services):
    accounting, values = services
    record = _admit(accounting, "commercial-retry")
    request = dict(
        outcome_record_id=record["id"], expected_revision=0,
        operation_id="commercial-exact-retry-one", actor="user:alice",
        kind="renewal", stage="proposed", basis="estimated", amount="100",
        currency="USD", unknown_reason=None, source_ref="crm:renewal-retry",
        source_version="a" * 64, note="Initial renewal estimate.",
    )
    first = values.record_commercial(**request)
    assert values.record_commercial(**request)["revision"] == first["revision"]
    with pytest.raises(RecordConflict, match="documented correction"):
        values.record_commercial(
            record["id"], expected_revision=first["revision"],
            operation_id="commercial-same-source-change", actor="user:alice",
            kind="renewal", stage="won", basis="observed", amount="110",
            currency="USD", unknown_reason=None, source_ref="crm:renewal-retry",
            source_version="b" * 64, note="Changed without linking the current record.",
        )


def test_non_direct_cost_requires_explicit_allocation_assumption(services):
    accounting, _ = services
    record = _admit(accounting, "allocation-assumption")
    with pytest.raises(ValueError, match="allocation requires its assumption"):
        accounting.record_cost(
            record["id"], expected_revision=record["revision"],
            operation_id="missing-allocation-assumption", actor="user:alice",
            category="allocation", attempt_state="succeeded", basis="observed",
            amount="5", currency="USD", source_ref="shared:cost-line",
            source_version="a" * 64, allocation_method="equal_share",
        )


def test_commercial_detail_overflow_is_counted_and_withholds_complete_export_scope(
    services, monkeypatch,
):
    accounting, values = services
    record = _admit(accounting, "commercial-bound")
    first = values.record_commercial(
        record["id"], expected_revision=0,
        operation_id="commercial-bound-first", actor="user:alice",
        kind="renewal", stage="proposed", basis="estimated", amount="100",
        currency="USD", unknown_reason=None, source_ref="crm:renewal-bound-one",
        source_version="a" * 64, note="First bounded renewal.",
    )
    values.record_commercial(
        record["id"], expected_revision=first["revision"],
        operation_id="commercial-bound-second", actor="user:alice",
        kind="renewal", stage="proposed", basis="estimated", amount="120",
        currency="USD", unknown_reason=None, source_ref="crm:renewal-bound-two",
        source_version="b" * 64, note="Second bounded renewal.",
    )
    monkeypatch.setattr(value_module, "_MAX_COMMERCIAL_REPORT", 1)

    report = values.cohort_report(owner_id="user:alice")

    assert report["commercial_counts"] == {"renewals": 2, "expansions": 0}
    assert len(report["commercial"]["renewals"]) == 1
    assert report["commercial_records_complete"] is False
    assert report["scope_complete"] is False
    assert report["comparison"]["cost"]["status"] == "unavailable"
