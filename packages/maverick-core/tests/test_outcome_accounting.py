"""Acceptance tests for append-only outcome, evidence, and cost accounting."""
from __future__ import annotations

import pickle
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Event

import pytest
from maverick import outcome_accounting as outcome_module
from maverick import provider_cost_cap
from maverick.budget import Budget, BudgetExceeded, UnpricedModelError
from maverick.governed_records import GovernedRecordStore
from maverick.outcome_accounting import (
    CostEvidenceAuthority,
    OutcomeAccounting,
    ReservationAuthority,
)
from maverick.paths import tenant_scope
from maverick.platform_contracts import read_contract
from maverick.privacy_ops import RecordConflict


@pytest.fixture
def accounting(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    store = GovernedRecordStore("test_outcome_accounting", "OAT", "outcome_accounting")
    with tenant_scope(tenant="customer-one"):
        reservation = ReservationAuthority(
            reservation_ref="budget-reservation:run-one",
            projected_amount="10",
            state="settled",
            actual_amount="8",
            currency="USD",
            verification_authority="test:provider-reservation-authority",
        )
        claimed: dict[str, str | None] = {}

        def resolve_reservation(reference, work_item_id):
            if reference != reservation.reservation_ref or work_item_id != "work-one":
                raise PermissionError("unknown reservation")
            return reservation

        def claim_reservation(authority, work_item_id, claim_id):
            if authority != reservation or work_item_id != "work-one":
                raise PermissionError("unknown reservation")
            claimed.setdefault(claim_id, None)
            return reservation

        def commit_reservation(authority, work_item_id, claim_id, event_id):
            if authority != reservation or work_item_id != "work-one":
                raise PermissionError("unknown reservation")
            if claim_id not in claimed:
                raise PermissionError("reservation was not prepared")
            prior = claimed[claim_id]
            if prior is not None and prior != event_id:
                raise PermissionError("reservation was committed elsewhere")
            claimed[claim_id] = event_id
            return reservation

        yield OutcomeAccounting(
            store=store,
            cost_evidence_resolver=lambda assurance, ref, digest: CostEvidenceAuthority(
                source_assurance=assurance,
                evidence_ref=ref,
                evidence_sha256=digest,
                verification_authority="test:trusted-cost-evidence",
            ),
            reservation_resolver=resolve_reservation,
            reservation_claimer=claim_reservation,
            reservation_committer=commit_reservation,
        )


def admit(accounting, suffix="one"):
    return accounting.admit(
        admission_id=f"admission-{suffix}",
        work_item_id=f"work-{suffix}",
        acceptance_contract_ref="contract:vendor-evidence:v1",
        owner_id="user:alice",
        actor="user:alice",
    )


def complete_coverage(*included):
    selected = set(included)
    return {
        family: {
            "status": "included" if family in selected or "all" in selected else "zero",
            "note": (
                "This family is included in the recorded complete cost."
                if family in selected or "all" in selected else
                "The reviewed evidence confirms zero cost for this family."
            ),
        }
        for family in outcome_module.COST_COVERAGE_FAMILIES
    }


def observe(accounting, record, *, result, operation_id, authoritative=True, **changes):
    return accounting.record_observation(
        record["id"],
        expected_revision=record["revision"],
        operation_id=operation_id,
        actor="user:alice",
        source_id=changes.pop("source_id", "jira:ticket-1"),
        source_version=changes.pop("source_version", "a" * 64),
        result=result,
        authoritative=authoritative,
        summary=changes.pop("summary", result),
        **changes,
    )


def test_http_success_does_not_override_missing_or_conflicting_readback(accounting):
    record = admit(accounting)
    record = observe(
        accounting,
        record,
        result="confirmed",
        operation_id="transport-success-observation",
        authoritative=False,
        source_id="http:jira-create",
        summary="HTTP 201 returned",
    )
    record = observe(
        accounting,
        record,
        result="missing",
        operation_id="authoritative-readback-missing",
        summary="No exact ticket matched",
    )

    report = accounting.report(record["id"])
    assert report["technical_outcome"]["status"] == "unresolved"
    assert [row["result"] for row in report["observations"]] == ["confirmed", "missing"]

    record = observe(
        accounting,
        record,
        result="contradictory",
        operation_id="authoritative-readback-conflict",
        source_version="b" * 64,
        summary="Ticket fields contradict the approved intent",
        correction_of=record["observations"][-1]["id"],
    )
    report = accounting.report(record["id"])
    assert report["technical_outcome"]["status"] == "failed"
    assert len(report["observations"]) == 3
    assert report["observations"][1]["current"] is False


def test_simulator_source_cannot_be_admitted_as_authoritative_live_evidence(accounting):
    record = admit(accounting)

    with pytest.raises(PermissionError, match="simulated evidence"):
        observe(
            accounting,
            record,
            result="confirmed",
            operation_id="simulated-authoritative-result",
            source_id="simulator:sim-work-one-result",
        )

    recorded = observe(
        accounting,
        record,
        result="confirmed",
        operation_id="simulated-nonauthoritative-result",
        authoritative=False,
        source_id="simulator:sim-work-one-result",
    )
    assert recorded["observations"][0]["authoritative"] is False


def test_all_admissions_stay_in_reconciled_denominator(accounting):
    records = [admit(accounting, str(index)) for index in range(10)]
    for index, record in enumerate(records):
        if index < 3:
            records[index] = accounting.record_disposition(
                record["id"], expected_revision=record["revision"],
                operation_id=f"cancel-outcome-case-{index:02d}", actor="user:alice",
                disposition="cancelled", reason="Customer stopped this case.",
            )
        elif index < 5:
            records[index] = accounting.record_disposition(
                record["id"], expected_revision=record["revision"],
                operation_id=f"failed-outcome-case-{index:02d}", actor="user:alice",
                disposition="failed", reason="The workflow could not complete.",
            )
        elif index < 7:
            current = observe(
                accounting, record, result="confirmed",
                operation_id=f"verified-outcome-case-{index:02d}",
            )
            evidence_version = accounting.report(current["id"])["evidence_version"]
            records[index] = accounting.record_decision(
                current["id"], expected_revision=current["revision"],
                operation_id=f"accepted-outcome-case-{index:02d}", actor="user:reviewer",
                decision="accepted", rationale="Reviewed against the contract.",
                evidence_version=evidence_version,
            )

    portfolio = accounting.portfolio_report()
    assert portfolio["admitted"] == 10
    assert portfolio["categories"] == {
        "accepted": 2,
        "cancelled": 3,
        "failed": 2,
        "rejected": 0,
        "unresolved": 3,
    }
    assert sum(portfolio["categories"].values()) == portfolio["admitted"]


def test_failed_attempts_count_and_unknown_human_cost_is_not_zero(accounting):
    record = admit(accounting)
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="failed-search-cost", actor="user:alice",
        category="search", attempt_state="failed", basis="observed",
        amount="1.25", currency="USD", source_ref="provider:search-attempt-1",
        source_version="a" * 64,
    )
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="unpriced-human-review", actor="user:alice",
        category="human", attempt_state="succeeded", basis="unknown",
        amount=None, currency=None, quantity="30", unit="minutes",
        unknown_reason="The reviewer rate has not been supplied.",
        source_ref="timesheet:review-1", source_version="b" * 64,
    )

    costs = accounting.report(record["id"])["costs"]
    assert costs["known_totals"] == {"USD": "1.25"}
    assert costs["complete"] is False
    assert costs["unknown_event_count"] == 1
    assert costs["failed_attempt_count"] == 1
    assert "incomplete" in costs["display"].lower()
    assert all(value != "0" for value in costs["known_totals"].values())


def test_provider_human_and_rework_costs_are_all_additive(accounting):
    record = admit(accounting)
    for index, (category, amount, reference) in enumerate((
        ("inference", "3", "provider:call-one"),
        ("human", "5", "timesheet:review-one"),
        ("rework", "2", "timesheet:rework-one"),
    )):
        record = accounting.record_cost(
            record["id"],
            expected_revision=record["revision"],
            operation_id=f"additive-cost-component-{index}",
            actor="user:alice",
            category=category,
            attempt_state="succeeded",
            basis="observed",
            amount=amount,
            currency="USD",
            source_ref=reference,
            source_version=chr(ord("a") + index) * 64,
            coverage="complete" if category == "rework" else "partial",
            coverage_declarations=(
                complete_coverage("provider_usage", "review", "rework")
                if category == "rework" else None
            ),
            source_assurance=(
                "authenticated_provider_invoice"
                if category == "inference" else "operator_assertion"
            ),
            evidence_ref="invoice:additive-one" if category == "inference" else None,
            evidence_sha256="f" * 64 if category == "inference" else None,
        )

    costs = accounting.report(record["id"])["costs"]
    assert costs["known_totals"] == {"USD": "10"}
    assert [row["amount"] for row in costs["events"]] == ["3", "5", "2"]
    assert costs["complete"] is True


def test_correction_and_expiry_retain_historical_verdict(accounting):
    record = admit(accounting)
    record = observe(
        accounting, record, result="confirmed", operation_id="initial-readback",
        observed_at=1_700_000_000, valid_until=1_900_000_000,
    )
    first_version = accounting.report(record["id"], now=1_800_000_000)["evidence_version"]
    record = accounting.record_decision(
        record["id"], expected_revision=record["revision"],
        operation_id="initial-human-acceptance", actor="user:reviewer",
        decision="accepted", rationale="The authoritative result met the contract.",
        evidence_version=first_version,
    )
    current = accounting.report(record["id"], now=1_800_000_000)
    assert current["business_outcome"]["status"] == "accepted"

    expired = accounting.report(record["id"], now=1_900_000_001)
    assert expired["business_outcome"]["status"] == "unresolved"
    assert expired["decisions"][0]["current"] is False
    assert expired["decisions"][0]["current_reason"] == "evidence_changed_or_expired"

    record = observe(
        accounting, record, result="contradictory", operation_id="corrected-readback",
        source_version="b" * 64, correction_of=record["observations"][0]["id"],
        summary="A corrected source now contradicts the former result.",
        observed_at=1_910_000_000, valid_until=2_100_000_000,
    )
    corrected = accounting.report(record["id"], now=1_920_000_000)
    assert corrected["technical_outcome"]["status"] == "failed"
    assert len(corrected["observations"]) == 2
    assert corrected["decisions"][0]["decision"] == "accepted"
    assert corrected["decisions"][0]["current"] is False


def test_budget_overrun_is_retained_and_budget_remains_blocked(accounting):
    record = admit(accounting)
    budget = Budget(max_output_tokens=0, max_dollars=100)

    with pytest.raises(BudgetExceeded) as caught:
        accounting.account_tokens(
            record["id"], expected_revision=record["revision"],
            operation_id="over-budget-model-call", actor="user:alice",
            budget=budget, in_tokens=0, out_tokens=1,
            source_ref="model-call:attempt-1", source_version="c" * 64,
        )

    saved = caught.value.accounting_record
    costs = accounting.report(saved["id"])["costs"]
    assert costs["event_count"] == 1
    assert costs["events"][0]["attempt_state"] == "succeeded"
    assert costs["events"][0]["budget_state"] == "limit_exceeded"
    assert costs["budget_overrun_count"] == 1
    assert Decimal(costs["known_totals"]["USD"]) >= Decimal("0")
    with pytest.raises(BudgetExceeded):
        budget.check()


def test_external_identity_alphabet_is_preserved_and_control_characters_fail(accounting):
    record = accounting.admit(
        admission_id="https://customer.example/work/42?version=1",
        work_item_id="ticket/customer@example.test/42",
        acceptance_contract_ref="contract:vendor-evidence:v1",
        owner_id="user:customer@example.test",
        actor="user:customer@example.test",
    )
    record = observe(
        accounting, record, result="confirmed", operation_id="email-principal-readback",
        source_id="https://system.example/evidence/42",
    )
    evidence_version = accounting.report(record["id"])["evidence_version"]
    saved = accounting.record_decision(
        record["id"], expected_revision=record["revision"],
        operation_id="email-principal-decision", actor="user:reviewer@example.test",
        decision="accepted", rationale="Reviewed.", evidence_version=evidence_version,
    )
    assert saved["owner_id"] == "user:customer@example.test"
    assert saved["decisions"][0]["actor"] == "user:reviewer@example.test"
    with pytest.raises(LookupError, match="unavailable"):
        accounting.report(saved["id"], owner_id="user:another@example.test")
    with pytest.raises(ValueError, match="control"):
        accounting.admit(
            admission_id="bad\nidentity", work_item_id="work",
            acceptance_contract_ref="contract", owner_id="user:alice", actor="user:alice",
        )
    with pytest.raises(ValueError, match="at most 256"):
        accounting.admit(
            admission_id="bounded-owner", work_item_id="work",
            acceptance_contract_ref="contract", owner_id="u" * 257, actor="user:alice",
        )


def test_exact_operation_retries_are_idempotent_despite_server_timestamps(accounting):
    record = admit(accounting)
    first = observe(
        accounting, record, result="confirmed", operation_id="idempotent-observation",
    )
    retried = observe(
        accounting, record, result="confirmed", operation_id="idempotent-observation",
    )
    assert retried["revision"] == first["revision"]
    assert len(retried["observations"]) == 1

    first_cost = accounting.record_cost(
        record["id"], expected_revision=first["revision"],
        operation_id="idempotent-cost-event", actor="user:alice", category="retry",
        attempt_state="failed", basis="observed", amount="0.10", currency="USD",
        source_ref="provider:attempt", source_version="d" * 64,
    )
    retried_cost = accounting.record_cost(
        record["id"], expected_revision=first["revision"],
        operation_id="idempotent-cost-event", actor="user:alice", category="retry",
        attempt_state="failed", basis="observed", amount="0.10", currency="USD",
        source_ref="provider:attempt", source_version="d" * 64,
    )
    assert retried_cost["revision"] == first_cost["revision"]
    assert len(retried_cost["cost_events"]) == 1


def test_future_correction_does_not_supersede_current_evidence_early(accounting):
    record = admit(accounting)
    record = observe(
        accounting, record, result="confirmed", operation_id="current-source-version",
        observed_at=1_800_000_000, valid_until=2_100_000_000,
    )
    record = observe(
        accounting, record, result="contradictory", operation_id="scheduled-correction",
        source_version="e" * 64, correction_of=record["observations"][0]["id"],
        observed_at=2_000_000_000, valid_until=2_200_000_000,
    )
    before = accounting.report(record["id"], now=1_900_000_000)
    assert before["technical_outcome"]["status"] == "verified"
    assert before["observations"][0]["current"] is True
    assert before["observations"][1]["current"] is False
    after = accounting.report(record["id"], now=2_050_000_000)
    assert after["technical_outcome"]["status"] == "failed"
    assert after["observations"][0]["current_reason"] == "superseded"


def test_scheduled_correction_reserves_its_target(accounting):
    record = admit(accounting)
    record = observe(
        accounting, record, result="confirmed", operation_id="scheduled-base-source",
        observed_at=1_800_000_000, valid_until=2_100_000_000,
    )
    record = observe(
        accounting, record, result="contradictory", operation_id="scheduled-source-revision",
        source_version="b" * 64, correction_of=record["observations"][0]["id"],
        observed_at=2_000_000_000, valid_until=2_200_000_000,
    )
    with pytest.raises(RecordConflict, match="already superseded"):
        observe(
            accounting, record, result="missing", operation_id="competing-source-revision",
            source_version="c" * 64, correction_of=record["observations"][0]["id"],
            observed_at=1_900_000_000, valid_until=2_200_000_000,
        )


def test_incomplete_cost_inputs_are_rejected_instead_of_silently_discarded(accounting):
    record = admit(accounting)
    common = {
        "record_id": record["id"], "expected_revision": record["revision"],
        "actor": "user:alice", "category": "human", "attempt_state": "succeeded",
        "source_ref": "timesheet:one", "source_version": "f" * 64,
    }
    with pytest.raises(ValueError, match="unit requires"):
        accounting.record_cost(
            operation_id="cost-unit-without-quantity", basis="unknown", amount=None,
            currency=None, unit="minutes", unknown_reason="Rate unavailable.", **common,
        )
    with pytest.raises(ValueError, match="priced cost"):
        accounting.record_cost(
            operation_id="priced-cost-unknown-reason", basis="observed", amount="1",
            currency="USD", unknown_reason="Contradictory input.", **common,
        )
    assert accounting.report(record["id"])["costs"]["settlement_status"] == "incomplete"


def test_informational_components_remain_visible_without_double_counting_total(accounting):
    record = admit(accounting)
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="reported-workflow-total", actor="user:alice", category="other",
        attempt_state="succeeded", basis="observed", amount="25", currency="USD",
        source_ref="report:total", source_version="a" * 64,
    )
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="reported-human-component", actor="user:alice", category="human",
        attempt_state="succeeded", basis="observed", amount="10", currency="USD",
        source_ref="report:human", source_version="a" * 64, aggregation="informational",
    )
    costs = accounting.report(record["id"])["costs"]
    assert costs["known_totals"] == {"USD": "25"}
    assert costs["informational_event_count"] == 1
    assert costs["events"][1]["amount"] == "10"


def test_token_accounting_retry_and_conflict_do_not_charge_budget_twice(accounting):
    record = admit(accounting)
    budget = Budget(max_output_tokens=10, max_dollars=100)
    values = {
        "record_id": record["id"], "expected_revision": record["revision"],
        "operation_id": "idempotent-token-accounting", "actor": "user:alice",
        "budget": budget, "in_tokens": 0, "out_tokens": 1,
        "source_ref": "model-call:stable-attempt", "source_version": "a" * 64,
        "model": "codex_cli:gpt-5.5",
    }
    first = accounting.account_tokens(**values)
    retried = accounting.account_tokens(**values)
    assert first["revision"] == retried["revision"]
    assert budget.output_tokens == 1
    assert len(retried["cost_events"]) == 1

    with pytest.raises(RecordConflict):
        accounting.account_tokens(**{**values, "out_tokens": 2})
    assert budget.output_tokens == 1
    with pytest.raises(RecordConflict):
        accounting.account_tokens(**{
            **values, "operation_id": "new-stale-accounting-operation",
        })
    assert budget.output_tokens == 1


def test_token_accounting_repairs_append_crash_after_budget_serialization(
    accounting,
    monkeypatch,
):
    record = admit(accounting)
    budget = Budget(max_output_tokens=10, max_dollars=100)
    values = {
        "record_id": record["id"], "expected_revision": record["revision"],
        "operation_id": "crash-safe-token-accounting", "actor": "user:alice",
        "budget": budget, "in_tokens": 0, "out_tokens": 1,
        "source_ref": "model-call:crash-safe", "source_version": "a" * 64,
        "model": "codex_cli:gpt-5.5",
    }
    original_record_cost = accounting.record_cost

    def crash_after_budget(*_args, **_kwargs):
        raise OSError("simulated outcome append crash")

    monkeypatch.setattr(accounting, "record_cost", crash_after_budget)
    with pytest.raises(OSError, match="simulated outcome append crash"):
        accounting.account_tokens(**values)
    assert budget.output_tokens == 1
    restored = pickle.loads(pickle.dumps(budget))

    monkeypatch.setattr(accounting, "record_cost", original_record_cost)
    saved = accounting.account_tokens(**{**values, "budget": restored})
    assert restored.output_tokens == 1
    assert len(saved["cost_events"]) == 1


def test_concurrent_exact_token_retries_charge_budget_once(accounting):
    record = admit(accounting)
    second_service = OutcomeAccounting(store=accounting.store)
    budget = Budget(max_output_tokens=10, max_dollars=100)
    values = {
        "record_id": record["id"], "expected_revision": record["revision"],
        "operation_id": "concurrent-token-accounting", "actor": "user:alice",
        "budget": budget, "in_tokens": 0, "out_tokens": 1,
        "source_ref": "model-call:concurrent-attempt", "source_version": "a" * 64,
        "model": "codex_cli:gpt-5.5",
    }

    def account_once(service):
        with tenant_scope(tenant="customer-one"):
            return service.account_tokens(**values)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(account_once, (accounting, second_service)))
    assert results[0]["revision"] == results[1]["revision"]
    assert budget.output_tokens == 1
    assert len(results[0]["cost_events"]) == 1


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"model": "unpriced:model-for-accounting-test"}, UnpricedModelError),
        ({"in_tokens": -1, "model": "codex_cli:gpt-5.5"}, BudgetExceeded),
        ({"cache_read_mult": float("nan"), "model": "codex_cli:gpt-5.5"}, BudgetExceeded),
        ({"model": 17}, BudgetExceeded),
    ],
)
def test_unpriced_or_invalid_usage_is_unknown_instead_of_zero(
    accounting, monkeypatch, changes, error,
):
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "true")
    record = admit(accounting)
    budget = Budget()
    values = {
        "record_id": record["id"], "expected_revision": record["revision"],
        "operation_id": "unknown-token-accounting", "actor": "user:alice",
        "budget": budget, "in_tokens": 1, "out_tokens": 1,
        "source_ref": "model-call:unknown-cost", "source_version": "b" * 64,
        **changes,
    }
    with pytest.raises(error) as caught:
        accounting.account_tokens(**values)
    costs = accounting.report(caught.value.accounting_record["id"])["costs"]
    assert costs["known_totals"] == {}
    assert costs["unknown_event_count"] == 1
    assert costs["complete"] is False
    assert costs["events"][0]["basis"] == "unknown"
    assert costs["events"][0]["budget_state"] == "metering_failed"
    assert (
        budget.input_tokens, budget.output_tokens, budget.cache_read_tokens,
        budget.cache_write_tokens, budget.dollars,
    ) == (0, 0, 0, 0, 0)


def test_extreme_valid_token_charge_is_recorded_with_exact_pricing_provenance(
    accounting,
):
    record = admit(accounting)
    budget = Budget(max_dollars=1e20)
    record = accounting.account_tokens(
        record["id"], expected_revision=record["revision"],
        operation_id="extreme-valid-token-charge", actor="user:alice",
        budget=budget, in_tokens=0, out_tokens=0,
        cache_read_tok=(1 << 63) - 1, cache_read_mult=1000,
        source_ref="model-call:extreme", source_version="b" * 64,
        model="claude-sonnet-4-6",
    )

    event = accounting.report(record["id"])["costs"]["events"][0]
    assert Decimal(event["amount"]) > Decimal("1e16")
    assert event["basis"] == "observed"
    assert event["budget_state"] == "within_limit"
    assert event["pricing_evidence"]["verified"] is True
    assert event["pricing_evidence"]["model_id"] == "claude-sonnet-4-6"


def test_estimate_only_token_charge_stays_estimated_with_rate_evidence(
    accounting, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "false")
    record = admit(accounting)
    budget = Budget(max_input_tokens=2_000_000, max_dollars=100)
    record = accounting.account_tokens(
        record["id"], expected_revision=record["revision"],
        operation_id="estimated-token-charge", actor="user:alice",
        budget=budget, in_tokens=1_000_000, out_tokens=0,
        source_ref="model-call:estimate", source_version="b" * 64,
        model="unknown-model-for-estimate-accounting",
    )

    event = accounting.report(record["id"])["costs"]["events"][0]
    assert event["amount"] == "3"
    assert event["basis"] == "estimated"
    assert event["pricing_evidence"]["verified"] is False
    assert event["pricing_evidence"]["confidence"] == 0.1


def test_expiring_rate_is_recorded_and_historical_receipt_survives_expiry(accounting, monkeypatch):
    from datetime import datetime, timezone

    from maverick import pricing

    clock = [datetime(2026, 11, 6, tzinfo=timezone.utc)]
    class ReceiptClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0]
    monkeypatch.setattr(pricing, "datetime", ReceiptClock)
    record = admit(accounting)
    record = accounting.account_tokens(
        record["id"], expected_revision=record["revision"],
        operation_id="expiring-rate-accounting", actor="user:alice",
        budget=Budget(max_dollars=100), in_tokens=1000, out_tokens=100,
        source_ref="model-call:expiring-rate", source_version="b" * 64,
        model="openai:gpt-5.6-sol",
    )
    clock[0] = datetime(2027, 1, 1, tzinfo=timezone.utc)
    event = accounting.report(record["id"])["costs"]["events"][0]
    assert event["attempt_state"] == "succeeded"
    assert event["pricing_evidence"]["valid_until"] == "2026-11-30"
    assert Decimal(event["amount"]) > 0


def test_nonexpiring_price_evidence_preserves_legacy_canonical_form():
    from maverick.budget import _lookup_price_quote

    evidence = _lookup_price_quote("claude-sonnet-4-6").metadata()
    normalized = outcome_module._pricing_evidence(evidence)
    evidence.pop("valid_until")
    assert normalized == outcome_module._pricing_evidence(evidence)
    assert "valid_until" not in normalized


@pytest.mark.parametrize("expiry", [True, 20260101, "2026-02-30", "2020-01-01", "x" * 10000],
                         ids=["boolean", "integer", "invalid-date", "backdated", "oversized"])
def test_price_evidence_rejects_malformed_or_backdated_expiry(expiry):
    from maverick.budget import _lookup_price_quote

    evidence = _lookup_price_quote("claude-sonnet-4-6").metadata()
    evidence["valid_until"] = expiry
    with pytest.raises(ValueError):
        outcome_module._pricing_evidence(evidence)


def test_concurrent_direct_budget_charge_cannot_pollute_accounted_call(accounting):
    record = admit(accounting)
    charged = Event()
    release = Event()

    class PausingBudget(Budget):
        def record_tokens(self, *args, **kwargs):
            result = super().record_tokens(*args, **kwargs)
            charged.set()
            assert release.wait(timeout=5)
            return result

    budget = PausingBudget(max_output_tokens=5_000_000, max_dollars=100)

    def account():
        with tenant_scope(tenant="customer-one"):
            return accounting.account_tokens(
                record["id"], expected_revision=record["revision"],
                operation_id="isolated-concurrent-charge", actor="user:alice",
                budget=budget, in_tokens=0, out_tokens=1_000_000,
                source_ref="model-call:owned", source_version="c" * 64,
                model="claude-sonnet-4-6",
            )

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(account)
        assert charged.wait(timeout=5)
        Budget.record_tokens(
            budget, 0, 2_000_000, model="claude-sonnet-4-6",
        )
        release.set()
        saved = pending.result(timeout=5)

    event = accounting.report(saved["id"])["costs"]["events"][0]
    assert event["amount"] == "15"
    assert budget.dollars == 45


def test_exact_correction_and_expired_decision_retries_return_committed_record(
    accounting, monkeypatch,
):
    record = admit(accounting)
    expiry = time.time() + 60
    record = observe(
        accounting, record, result="confirmed", operation_id="retry-base-observation",
        valid_until=expiry,
    )
    correction_values = {
        "record_id": record["id"], "expected_revision": record["revision"],
        "operation_id": "retry-observation-correction", "actor": "user:alice",
        "source_id": "jira:ticket-1", "source_version": "b" * 64,
        "result": "confirmed", "authoritative": True, "summary": "Corrected evidence.",
        "valid_until": expiry,
        "correction_of": record["observations"][0]["id"],
    }
    corrected = accounting.record_observation(**correction_values)
    assert accounting.record_observation(**correction_values)["revision"] == corrected["revision"]

    evidence_version = accounting.report(record["id"])["evidence_version"]
    decision_values = {
        "record_id": record["id"], "expected_revision": corrected["revision"],
        "operation_id": "retry-expiring-decision", "actor": "user:reviewer",
        "decision": "accepted", "rationale": "Reviewed current evidence.",
        "evidence_version": evidence_version,
    }
    decision = accounting.record_decision(**decision_values)
    expired_clock = expiry + 1
    monkeypatch.setattr(accounting.store, "authoritative_time", lambda: expired_clock)
    assert accounting.record_decision(**decision_values)["revision"] == decision["revision"]

    cost = accounting.record_cost(
        record["id"], expected_revision=decision["revision"],
        operation_id="retry-original-cost", actor="user:alice", category="search",
        attempt_state="failed", basis="observed", amount="1", currency="USD",
        source_ref="search:one", source_version="c" * 64,
    )
    cost_values = {
        "record_id": record["id"], "expected_revision": cost["revision"],
        "operation_id": "retry-cost-correction", "actor": "user:alice",
        "category": "search", "attempt_state": "failed", "basis": "settled",
        "amount": "2", "currency": "USD", "source_ref": "search:one",
        "source_version": "d" * 64, "correction_of": cost["cost_events"][0]["id"],
        "correction_reason": "The provider settled the failed search at a corrected amount.",
        "coverage": "complete",
        "coverage_declarations": complete_coverage("provider_usage", "failed_attempts"),
        "source_assurance": "authenticated_provider_invoice",
        "evidence_ref": "invoice:failed-search-correction",
        "evidence_sha256": "f" * 64,
    }
    corrected_cost = accounting.record_cost(**cost_values)
    assert accounting.record_cost(**cost_values)["revision"] == corrected_cost["revision"]
    corrected_costs = accounting.report(record["id"])["costs"]
    assert corrected_costs["known_totals"] == {"USD": "2"}
    assert corrected_costs["settlement_status"] == "settled"
    assert corrected_costs["events"][0]["current_reason"] == "superseded"


def test_cost_completeness_requires_explicit_coverage_and_counts_attempts_once(accounting):
    record = admit(accounting)
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="failed-attempt-search-component", actor="user:alice",
        category="search", attempt_state="failed", basis="observed",
        amount="1", currency="USD", source_ref="search:component",
        source_version="a" * 64, attempt_ref="attempt:one",
    )
    partial = accounting.report(record["id"])["costs"]
    assert partial["complete"] is False
    assert "incomplete" in partial["display"].lower()

    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="failed-attempt-human-component", actor="user:alice",
        category="human", attempt_state="failed", basis="observed",
        amount="2", currency="USD", source_ref="human:component",
        source_version="a" * 64, aggregation="informational", attempt_ref="attempt:one",
    )
    costs = accounting.report(record["id"])["costs"]
    assert costs["failed_attempt_count"] == 1
    assert costs["failed_attempt_event_count"] == 2


def test_complete_cost_requires_exact_nonunknown_family_evidence(accounting):
    record = admit(accounting)
    request = {
        "record_id": record["id"],
        "expected_revision": record["revision"],
        "operation_id": "complete-cost-without-family-evidence",
        "actor": "user:alice",
        "category": "support",
        "attempt_state": "succeeded",
        "basis": "observed",
        "amount": "3",
        "currency": "USD",
        "source_ref": "support:complete-evidence",
        "source_version": "a" * 64,
        "coverage": "complete",
    }
    with pytest.raises(ValueError, match="every required cost-family declaration"):
        accounting.record_cost(**request)

    missing = complete_coverage("support")
    missing.pop("allocation")
    with pytest.raises(ValueError, match="every required cost family exactly once"):
        accounting.record_cost(
            **{**request, "operation_id": "complete-cost-missing-family"},
            coverage_declarations=missing,
        )

    unknown = complete_coverage("support")
    unknown["allocation"] = {
        "status": "unknown",
        "note": "The shared allocation review has not been completed.",
    }
    with pytest.raises(ValueError, match="cannot contain an unknown cost family"):
        accounting.record_cost(
            **{**request, "operation_id": "complete-cost-unknown-family"},
            coverage_declarations=unknown,
        )

    with pytest.raises(ValueError, match="without a current additive component"):
        accounting.record_cost(
            **{**request, "operation_id": "complete-cost-false-included-families"},
            coverage_declarations=complete_coverage("all"),
        )

    contradictory = complete_coverage()
    with pytest.raises(ValueError, match="cannot be declared zero"):
        accounting.record_cost(
            **{**request, "operation_id": "complete-cost-false-zero"},
            coverage_declarations=contradictory,
        )
    assert accounting.report(record["id"])["costs"]["event_count"] == 0


def test_cost_correction_requires_reason_at_core_boundary_and_retries_once(accounting):
    record = admit(accounting)
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="core-cost-before-correction", actor="user:alice",
        category="support", attempt_state="succeeded", basis="observed",
        amount="3", currency="USD", source_ref="support:corrected-source",
        source_version="a" * 64,
    )
    original_id = record["cost_events"][0]["id"]
    correction = {
        "record_id": record["id"],
        "expected_revision": record["revision"],
        "operation_id": "core-cost-documented-correction",
        "actor": "user:alice",
        "category": "support",
        "attempt_state": "succeeded",
        "basis": "observed",
        "amount": "4",
        "currency": "USD",
        "source_ref": "support:corrected-source",
        "source_version": "b" * 64,
        "correction_of": original_id,
    }
    with pytest.raises(ValueError, match="requires its documented reason"):
        accounting.record_cost(**correction)

    correction["correction_reason"] = "The reviewed source omitted one support unit."
    corrected = accounting.record_cost(**correction)
    retried = accounting.record_cost(**correction)
    assert retried["revision"] == corrected["revision"]
    costs = accounting.report(record["id"])["costs"]
    assert costs["known_totals"] == {"USD": "4"}
    assert costs["event_count"] == 1
    assert costs["superseded_event_count"] == 1
    assert costs["events"][1]["correction_reason"].startswith("The reviewed source")


def test_unknown_attempt_state_cannot_claim_complete_cost(accounting):
    record = admit(accounting)
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="active-attempt-total", actor="user:alice", category="other",
        attempt_state="unknown", basis="observed", amount="5", currency="USD",
        source_ref="workflow:active-total", source_version="a" * 64,
        coverage="complete", attempt_ref="attempt:active",
        coverage_declarations=complete_coverage("all"),
        all_in_total=True,
    )
    costs = accounting.report(record["id"])["costs"]
    assert costs["coverage_complete"] is True
    assert costs["complete"] is False
    assert costs["settlement_status"] == "incomplete"


def test_unknown_informational_provider_evidence_blocks_complete_until_superseded(
    accounting,
):
    record = admit(accounting)
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="reported-all-in-total", actor="user:alice", category="other",
        attempt_state="succeeded", basis="observed", amount="10", currency="USD",
        source_ref="workflow:all-in", source_version="a" * 64,
        all_in_total=True,
    )
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="unknown-informational-provider-receipt", actor="user:alice",
        category="inference", attempt_state="unknown", basis="unknown",
        amount=None, currency=None, unknown_reason="Provider settlement is pending.",
        source_ref="provider:receipt-one", source_version="b" * 64,
        aggregation="informational", source_assurance="authenticated_provider_invoice",
        evidence_ref="provider:invoice-one", evidence_sha256="c" * 64,
    )
    unknown_id = record["cost_events"][-1]["id"]
    completion = {
        "record_id": record["id"],
        "expected_revision": record["revision"],
        "operation_id": "complete-with-unknown-provider-receipt",
        "actor": "user:alice",
        "category": "other",
        "attempt_state": "succeeded",
        "basis": "observed",
        "amount": "0",
        "currency": "USD",
        "source_ref": "coverage:provider-costs",
        "source_version": "d" * 64,
        "aggregation": "coverage",
        "coverage": "complete",
        "coverage_declarations": complete_coverage("all"),
    }
    with pytest.raises(ValueError, match="every current provider receipt and attempt"):
        accounting.record_cost(**completion)
    incomplete = accounting.report(record["id"])["costs"]
    assert incomplete["known_totals"] == {"USD": "10"}
    assert incomplete["complete"] is False
    assert incomplete["event_count"] == 2
    assert incomplete["events"][-1]["id"] == unknown_id
    assert incomplete["events"][-1]["current"] is True
    assert incomplete["events"][-1]["amount"] is None

    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="settled-informational-provider-receipt", actor="user:alice",
        category="inference", attempt_state="succeeded", basis="settled",
        amount="6", currency="USD", source_ref="provider:receipt-one",
        source_version="e" * 64, aggregation="informational",
        source_assurance="authenticated_provider_invoice",
        evidence_ref="provider:invoice-one-settled", evidence_sha256="f" * 64,
        correction_of=unknown_id,
        correction_reason="The provider supplied a settled replacement invoice.",
    )
    record = accounting.record_cost(
        **{
            **completion,
            "expected_revision": record["revision"],
            "operation_id": "complete-after-settled-provider-receipt",
        }
    )
    complete = accounting.report(record["id"])["costs"]
    assert complete["known_totals"] == {"USD": "10"}
    assert complete["complete"] is True
    assert complete["informational_event_count"] == 1
    assert next(row for row in complete["events"] if row["id"] == unknown_id)[
        "current_reason"
    ] == "superseded"


def test_semantic_provider_detail_contradicts_zero_provider_family(accounting):
    record = admit(accounting)
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="all-in-for-provider-zero", actor="user:alice", category="other",
        attempt_state="succeeded", basis="observed", amount="10", currency="USD",
        source_ref="invoice:all-in", source_version="a" * 64, all_in_total=True,
    )
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="provider-detail-for-zero", actor="user:alice", category="inference",
        attempt_state="succeeded", basis="observed", amount="5", currency="USD",
        source_ref="provider:detail", source_version="b" * 64,
        aggregation="informational", source_assurance="operator_assertion",
    )
    with pytest.raises(ValueError, match="provider_usage cannot be declared zero"):
        accounting.record_cost(
            record["id"], expected_revision=record["revision"],
            operation_id="coverage-claim-provider-zero", actor="user:alice",
            category="other", attempt_state="succeeded", basis="observed",
            amount="0", currency="USD", source_ref="coverage:claim",
            source_version="c" * 64, aggregation="coverage", coverage="complete",
            coverage_declarations=complete_coverage(),
        )


def test_source_owned_cost_cannot_be_downgraded_by_operator_correction(accounting):
    record = admit(accounting)
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="source-owned-provider-cost", actor="system:source",
        category="inference", attempt_state="succeeded", basis="observed",
        amount="8", currency="USD", source_ref="source:provider-line",
        source_version="d" * 64, source_assurance="application_observation",
    )
    with pytest.raises(PermissionError, match="another source authority"):
        accounting.record_cost(
            record["id"], expected_revision=record["revision"],
            operation_id="operator-source-downgrade", actor="user:alice",
            category="inference", attempt_state="succeeded", basis="observed",
            amount="0", currency="USD", source_ref="source:provider-line",
            source_version="e" * 64, source_assurance="operator_assertion",
            correction_of=record["cost_events"][-1]["id"],
            correction_reason="Attempted operator replacement.",
        )
    assert accounting.report(record["id"])["costs"]["known_totals"] == {"USD": "8"}


def test_extreme_zero_decimal_is_bounded_and_detail_projects_shared_contract(accounting):
    record = admit(accounting)
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="bounded-zero-total-cost", actor="user:alice", category="other",
        attempt_state="succeeded", basis="settled", amount=Decimal("0e-999999999"),
        currency="USD", source_ref="reported:total", source_version="a" * 64,
        coverage="complete", source_assurance="authenticated_provider_invoice",
        coverage_declarations=complete_coverage("provider_usage"),
        evidence_ref="provider-invoice:zero", evidence_sha256="b" * 64,
    )
    report = accounting.report(record["id"])
    assert report["costs"]["known_totals"] == {"USD": "0"}
    assert report["costs"]["complete"] is True
    contract = read_contract(
        report["platform_contract"], expected_kind="outcome-record",
        expected_tenant_id="customer-one",
    )
    assert contract["work_item_id"] == "work-one"
    assert contract["cost"] == {"state": "exact", "currency": "USD", "amount": "0"}


def test_budget_charge_and_cost_commit_exclude_concurrent_record_mutation(accounting):
    record = admit(accounting)
    charged = Event()
    release = Event()
    disposition_started = Event()

    class PausingBudget(Budget):
        def record_tokens(self, *args, **kwargs):
            result = super().record_tokens(*args, **kwargs)
            charged.set()
            assert release.wait(timeout=5)
            return result

    budget = PausingBudget(max_output_tokens=10, max_dollars=100)

    def account():
        with tenant_scope(tenant="customer-one"):
            return accounting.account_tokens(
                record["id"], expected_revision=record["revision"],
                operation_id="serialized-model-accounting", actor="user:alice",
                budget=budget, in_tokens=0, out_tokens=1,
                source_ref="model-call:serialized", source_version="a" * 64,
                model="codex_cli:gpt-5.5",
            )

    def dispose():
        with tenant_scope(tenant="customer-one"):
            disposition_started.set()
            return accounting.record_disposition(
                record["id"], expected_revision=record["revision"],
                operation_id="concurrent-disposition", actor="user:alice",
                disposition="completed", reason="Concurrent completion.",
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        accounted = pool.submit(account)
        assert charged.wait(timeout=5)
        competing = pool.submit(dispose)
        assert disposition_started.wait(timeout=5)
        release.set()
        saved = accounted.result(timeout=5)
        with pytest.raises(RecordConflict):
            competing.result(timeout=5)

    assert budget.output_tokens == 1
    assert len(saved["cost_events"]) == 1
    assert accounting.report(record["id"])["costs"]["event_count"] == 1


def test_cost_coverage_is_bound_to_exact_current_additive_set(accounting):
    record = admit(accounting)
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="initial-complete-total", actor="user:alice", category="other",
        attempt_state="succeeded", basis="observed", amount="10", currency="USD",
        source_ref="workflow:initial-total", source_version="a" * 64,
        coverage="complete", attempt_ref="attempt:one",
        coverage_declarations=complete_coverage("all"),
        all_in_total=True,
    )
    assert accounting.report(record["id"])["costs"]["complete"] is True
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="later-partial-failed-cost", actor="user:alice", category="retry",
        attempt_state="failed", basis="observed", amount="2", currency="USD",
        source_ref="workflow:retry", source_version="b" * 64,
        coverage="partial", attempt_ref="attempt:two",
    )
    costs = accounting.report(record["id"])["costs"]
    assert costs["coverage_complete"] is False
    assert costs["complete"] is False
    assert costs["known_totals"] == {"USD": "12"}


def test_latest_same_evidence_decision_supersedes_prior_decision(accounting):
    record = observe(
        accounting, admit(accounting), result="confirmed",
        operation_id="decision-evidence",
    )
    evidence_version = accounting.report(record["id"])["evidence_version"]
    record = accounting.record_decision(
        record["id"], expected_revision=record["revision"],
        operation_id="first-evidence-decision", actor="user:reviewer",
        decision="accepted", rationale="First review.",
        evidence_version=evidence_version,
    )
    first_id = record["decisions"][0]["id"]
    record = accounting.record_decision(
        record["id"], expected_revision=record["revision"],
        operation_id="corrected-evidence-decision", actor="user:reviewer",
        decision="rejected", rationale="Corrected human decision.",
        evidence_version=evidence_version,
    )
    report = accounting.report(record["id"])
    assert [row["current"] for row in report["decisions"]] == [False, True]
    assert report["decisions"][1]["supersedes_ref"] == first_id
    assert report["business_outcome"]["status"] == "rejected"
    assert report["platform_contract"]["supersedes_ref"] == {
        "id": first_id, "kind": "outcome-decision",
    }


def test_new_evidence_decision_supersedes_stale_human_decision(accounting):
    record = observe(
        accounting, admit(accounting), result="confirmed",
        operation_id="initial-version-observation",
    )
    evidence_version = accounting.report(record["id"])["evidence_version"]
    record = accounting.record_decision(
        record["id"], expected_revision=record["revision"],
        operation_id="initial-version-decision", actor="user:reviewer",
        decision="accepted", rationale="Accepted the initial evidence.",
        evidence_version=evidence_version,
    )
    first_id = record["decisions"][0]["id"]
    record = observe(
        accounting, record, result="confirmed",
        operation_id="corrected-version-observation", source_version="b" * 64,
        correction_of=record["observations"][0]["id"],
    )
    new_evidence_version = accounting.report(record["id"])["evidence_version"]
    record = accounting.record_decision(
        record["id"], expected_revision=record["revision"],
        operation_id="corrected-version-decision", actor="user:reviewer",
        decision="accepted", rationale="Accepted the corrected evidence.",
        evidence_version=new_evidence_version,
    )

    report = accounting.report(record["id"])
    assert report["decisions"][0]["current_reason"] == "superseded"
    assert report["decisions"][1]["supersedes_ref"] == first_id
    assert report["platform_contract"]["supersedes_ref"] == {
        "id": first_id, "kind": "outcome-decision",
    }


def test_estimated_cost_is_not_projected_as_exact_and_large_additive_is_bounded(
        accounting):
    record = admit(accounting)
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="estimated-complete-total", actor="user:alice", category="other",
        attempt_state="succeeded", basis="estimated", amount="9", currency="USD",
        source_ref="estimate:total", source_version="a" * 64, coverage="complete",
        coverage_declarations=complete_coverage("all"),
        all_in_total=True,
    )
    report = accounting.report(record["id"])
    assert report["costs"]["settlement_status"] == "estimated"
    assert report["platform_contract"]["cost"] == {
        "state": "unknown",
        "reason": "cost_not_settled_by_authenticated_provider_invoice",
    }
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="large-bounded-additive-total", actor="user:alice", category="other",
        attempt_state="succeeded", basis="observed", amount="1e18", currency="USD",
        source_ref="large-bounded:total", source_version="b" * 64,
    )
    assert accounting.report(record["id"])["costs"]["known_totals"] == {
        "USD": "1000000000000000009",
    }


def test_fractional_record_and_portfolio_totals_do_not_round_at_28_digits(accounting):
    first = admit(accounting, "fractional-rollup-one")
    first = accounting.record_cost(
        first["id"], expected_revision=first["revision"],
        operation_id="fractional-large-component", actor="user:alice",
        category="other", attempt_state="succeeded", basis="observed",
        amount="1000000000000000000.000000000001", currency="USD",
        source_ref="fractional:large", source_version="a" * 64,
    )
    first = accounting.record_cost(
        first["id"], expected_revision=first["revision"],
        operation_id="fractional-small-component", actor="user:alice",
        category="other", attempt_state="succeeded", basis="observed",
        amount="0.000000000001", currency="USD",
        source_ref="fractional:small-one", source_version="b" * 64,
    )
    second = admit(accounting, "fractional-rollup-two")
    accounting.record_cost(
        second["id"], expected_revision=second["revision"],
        operation_id="fractional-portfolio-component", actor="user:alice",
        category="other", attempt_state="succeeded", basis="observed",
        amount="0.000000000001", currency="USD",
        source_ref="fractional:small-two", source_version="c" * 64,
    )

    assert accounting.report(first["id"])["costs"]["known_totals"] == {
        "USD": "1000000000000000000.000000000002",
    }
    assert accounting.portfolio_report()["costs"]["known_totals"] == {
        "USD": "1000000000000000000.000000000003",
    }


def test_fractional_provider_reservation_delta_is_exact(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    authority = ReservationAuthority(
        reservation_ref="budget-reservation:fractional",
        projected_amount="1000000000000000000.000000000001",
        state="settled",
        actual_amount="1000000000000000000.000000000002",
        currency="USD",
        verification_authority="test:fractional-reservation-authority",
    )
    claimed: set[str] = set()

    def resolve(reference, work_item_id):
        if reference != authority.reservation_ref or work_item_id != "work-fractional":
            raise PermissionError("unknown reservation")
        return authority

    def claim(selected, work_item_id, claim_id):
        assert selected == authority and work_item_id == "work-fractional"
        claimed.add(claim_id)
        return authority

    def commit(selected, work_item_id, claim_id, _event_id):
        assert selected == authority and work_item_id == "work-fractional"
        assert claim_id in claimed
        return authority

    service = OutcomeAccounting(
        store=GovernedRecordStore(
            "test_fractional_reservation", "OFR", "outcome_accounting",
        ),
        reservation_resolver=resolve,
        reservation_claimer=claim,
        reservation_committer=commit,
    )
    record = service.admit(
        admission_id="admission-fractional", work_item_id="work-fractional",
        acceptance_contract_ref="contract:fractional:v1",
        owner_id="user:alice", actor="user:alice",
    )
    saved = service.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="fractional-reservation-settlement", actor="user:alice",
        category="inference", attempt_state="succeeded", basis="observed",
        amount=authority.actual_amount, currency="USD",
        source_ref="provider:fractional", source_version="d" * 64,
        reservation_ref=authority.reservation_ref,
        reserved_amount=authority.projected_amount, reserved_currency="USD",
    )
    event = service.report(saved["id"])["costs"]["events"][0]
    assert event["budget_reconciliation"]["delta"] == "0.000000000001"
    assert event["budget_reconciliation"]["status"] == "overrun"


def test_provider_invoice_and_budget_reservation_are_distinct_and_reconciled(accounting):
    record = admit(accounting)
    record = accounting.record_cost(
        record["id"], expected_revision=record["revision"],
        operation_id="settled-provider-invoice", actor="user:finance", category="inference",
        attempt_state="succeeded", basis="settled", amount="8", currency="USD",
        source_ref="provider:invoice-line", source_version="a" * 64,
        coverage="complete", source_assurance="authenticated_provider_invoice",
        coverage_declarations=complete_coverage("provider_usage"),
        evidence_ref="invoice:2026-09", evidence_sha256="c" * 64,
        reservation_ref="budget-reservation:run-one", reserved_amount="10",
        reserved_currency="USD",
    )
    report = accounting.report(record["id"])
    event = report["costs"]["events"][0]
    assert event["source_assurance"] == "authenticated_provider_invoice"
    assert event["budget_reconciliation"] == {
        "reservation_ref": "budget-reservation:run-one",
        "reserved_amount": "10", "final_amount": "8", "currency": "USD",
        "delta": "2", "status": "released",
        "verification_authority": "test:provider-reservation-authority",
    }
    assert report["costs"]["authenticated_provider_invoice_count"] == 1
    assert report["costs"]["reconciled_reservation_count"] == 1
    assert report["platform_contract"]["cost"] == {
        "state": "exact", "currency": "USD", "amount": "8",
    }


def test_portfolio_is_cursor_bounded_and_returns_summaries(accounting):
    for index in range(5):
        admit(accounting, f"page-{index}")
    first = accounting.portfolio_report(limit=2)
    assert first["admitted"] == 2
    assert first["page"]["has_more"] is True
    assert first["page"]["next_cursor"]
    assert all("observations" not in row and "platform_contract" not in row for row in first["records"])
    assert all("events" not in row["costs"] for row in first["records"])

    second = accounting.portfolio_report(limit=2, cursor=first["page"]["next_cursor"])
    assert {row["id"] for row in first["records"]}.isdisjoint(
        row["id"] for row in second["records"]
    )


def test_portfolio_reports_aggregate_overflow_without_raising(accounting):
    for suffix in ("overflow-one", "overflow-two"):
        record = admit(accounting, suffix)
        accounting.record_cost(
            record["id"], expected_revision=record["revision"],
            operation_id=f"{suffix}-bounded-cost", actor="user:alice",
            category="other", attempt_state="succeeded", basis="observed",
            amount="9000000000000000000", currency="USD",
            source_ref=f"cost:{suffix}", source_version="d" * 64,
            coverage="complete",
            coverage_declarations=complete_coverage("all"),
            all_in_total=True,
        )

    portfolio = accounting.portfolio_report()
    assert portfolio["costs"]["known_totals"] == {}
    assert portfolio["costs"]["aggregate_overflow_currencies"] == ["USD"]
    assert portfolio["costs"]["totals_complete"] is False
    assert portfolio["costs"]["incomplete_records"] == 1


def test_real_provider_reservation_is_claimed_and_can_advance_from_held(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    ledger = tmp_path / "provider-spend.json"
    monkeypatch.setattr(provider_cost_cap, "caps_from_config", lambda: {"openai": 100.0})
    monkeypatch.setattr(provider_cost_cap, "period_from_config", lambda: "day")
    monkeypatch.setattr(provider_cost_cap, "_shared_world", lambda: None)
    monkeypatch.setattr(provider_cost_cap, "_ledger_path", lambda: ledger)
    service = OutcomeAccounting(
        store=GovernedRecordStore(
            "provider_backed_outcomes", "OAP", "outcome_accounting",
        ),
        reservation_resolver=outcome_module._inspect_provider_reservation,
        reservation_claimer=outcome_module._claim_provider_reservation,
        reservation_committer=outcome_module._commit_provider_reservation,
    )

    with tenant_scope(tenant="customer-one"):
        settled_record = service.admit(
            admission_id="provider-settled", work_item_id="goal:42",
            acceptance_contract_ref="contract:provider-cost:v1",
            owner_id="user:alice", actor="user:alice",
        )
        settled_hold = provider_cost_cap.reserve(
            "openai", 5, now=0, request_id="provider-settled-call",
            work_item_id="goal:42",
        )
        assert settled_hold is not None
        provider_cost_cap.settle(settled_hold, 3)
        settled_ref = provider_cost_cap.reservation_reference(settled_hold)
        settled_record = service.record_cost(
            settled_record["id"], expected_revision=settled_record["revision"],
            operation_id="account-provider-settled", actor="system:provider-meter",
            category="inference", attempt_state="succeeded", basis="observed",
            amount=None, currency=None, source_ref=settled_ref,
            source_version="a" * 64, reservation_ref=settled_ref,
        )
        event = service.report(settled_record["id"])["costs"]["events"][0]
        assert event["amount"] == "3"
        assert event["budget_reconciliation"]["status"] == "released"
        assert event["budget_reconciliation"]["verification_authority"].startswith(
            "provider-cost-cap:"
        )
        assert provider_cost_cap.inspect_reservation(
            settled_ref, expected_work_item_id="goal:42",
        ).outcome_claim is not None

        # Exact operation retries are safe after the durable provider claim.
        assert service.record_cost(
            settled_record["id"], expected_revision=0,
            operation_id="account-provider-settled", actor="system:provider-meter",
            category="inference", attempt_state="succeeded", basis="observed",
            amount=None, currency=None, source_ref=settled_ref,
            source_version="a" * 64, reservation_ref=settled_ref,
        ) == settled_record
        with pytest.raises(RecordConflict):
            service.record_cost(
                settled_record["id"], expected_revision=settled_record["revision"],
                operation_id="reuse-provider-reservation", actor="user:alice",
                category="inference", attempt_state="succeeded", basis="observed",
                amount=None, currency=None, source_ref=settled_ref,
                source_version="a" * 64, reservation_ref=settled_ref,
            )

        other_record = service.admit(
            admission_id="provider-other", work_item_id="goal:42",
            acceptance_contract_ref="contract:provider-cost:v1",
            owner_id="user:alice", actor="user:alice",
        )
        with pytest.raises(provider_cost_cap.ProviderAccountingUnavailable):
            service.record_cost(
                other_record["id"], expected_revision=other_record["revision"],
                operation_id="steal-provider-reservation", actor="user:alice",
                category="inference", attempt_state="succeeded", basis="observed",
                amount=None, currency=None, source_ref=settled_ref,
                source_version="a" * 64, reservation_ref=settled_ref,
            )

        pending_record = service.admit(
            admission_id="provider-pending", work_item_id="goal:43",
            acceptance_contract_ref="contract:provider-cost:v1",
            owner_id="user:alice", actor="user:alice",
        )
        pending_hold = provider_cost_cap.reserve(
            "openai", 6, now=0, request_id="provider-pending-call",
            work_item_id="goal:43",
        )
        assert pending_hold is not None
        pending_ref = provider_cost_cap.reservation_reference(pending_hold)
        pending_record = service.record_cost(
            pending_record["id"], expected_revision=pending_record["revision"],
            operation_id="account-provider-held", actor="system:provider-meter",
            category="inference", attempt_state="unknown", basis="unknown",
            amount=None, currency=None, unknown_reason="Provider usage is pending.",
            source_ref=pending_ref, source_version="b" * 64,
            reservation_ref=pending_ref,
        )
        pending_event = service.report(pending_record["id"])["costs"]["events"][0]
        assert pending_event["amount"] is None
        assert pending_event["budget_reconciliation"]["status"] == "held"
        assert service.report(pending_record["id"])["costs"]["complete"] is False

        provider_cost_cap.settle(pending_hold, 4)
        pending_record = service.record_cost(
            pending_record["id"], expected_revision=pending_record["revision"],
            operation_id="settle-provider-held", actor="system:provider-meter",
            category="inference", attempt_state="succeeded", basis="observed",
            amount=None, currency=None, source_ref=pending_ref,
            source_version="c" * 64, reservation_ref=pending_ref,
            correction_of=pending_event["id"],
            correction_reason="The provider hold settled to its final observed amount.",
        )
        pending_report = service.report(pending_record["id"])
        assert pending_report["costs"]["known_totals"] == {"USD": "4"}
        assert pending_report["costs"]["events"][0]["current_reason"] == "superseded"
        assert pending_report["costs"]["events"][1]["budget_reconciliation"]["status"] == (
            "released"
        )


def test_provider_claim_repairs_after_outcome_append_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    ledger = tmp_path / "provider-spend-crash.json"
    monkeypatch.setattr(provider_cost_cap, "caps_from_config", lambda: {"openai": 100.0})
    monkeypatch.setattr(provider_cost_cap, "_shared_world", lambda: None)
    monkeypatch.setattr(provider_cost_cap, "_ledger_path", lambda: ledger)
    service = OutcomeAccounting(
        store=GovernedRecordStore(
            "provider_crash_outcomes", "OAC", "outcome_accounting",
        ),
        reservation_resolver=outcome_module._inspect_provider_reservation,
        reservation_claimer=outcome_module._claim_provider_reservation,
        reservation_committer=outcome_module._commit_provider_reservation,
    )

    with tenant_scope(tenant="customer-one"):
        record = service.admit(
            admission_id="provider-crash", work_item_id="goal:99",
            acceptance_contract_ref="contract:provider-cost:v1",
            owner_id="user:alice", actor="user:alice",
        )
        held = provider_cost_cap.reserve(
            "openai", 2, request_id="provider-crash-call", work_item_id="goal:99",
        )
        assert held is not None
        provider_cost_cap.settle(held, 1)
        reference = provider_cost_cap.reservation_reference(held)
        original_append = service._append

        def crash_after_claim(*args, **kwargs):
            raise OSError("simulated crash after provider claim")

        monkeypatch.setattr(service, "_append", crash_after_claim)
        request = dict(
            record_id=record["id"], expected_revision=record["revision"],
            operation_id="account-after-crash", actor="system:provider-meter",
            category="inference", attempt_state="succeeded", basis="observed",
            amount=None, currency=None, source_ref=reference,
            source_version="d" * 64, reservation_ref=reference,
        )
        with pytest.raises(OSError, match="simulated crash"):
            service.record_cost(**request)
        assert provider_cost_cap.inspect_reservation(
            reference, expected_work_item_id="goal:99",
        ).outcome_claim_state == "prepared"
        assert provider_cost_cap.prune(now=time.time() + 86400, path=ledger) == 0

        monkeypatch.setattr(service, "_append", original_append)
        saved = service.record_cost(**request)
        assert service.report(saved["id"])["costs"]["known_totals"] == {"USD": "1"}
        committed = provider_cost_cap.inspect_reservation(
            reference, expected_work_item_id="goal:99",
        )
        assert committed.outcome_claim_state == "committed"
        assert committed.outcome_claim_event == saved["cost_events"][0]["id"]


def test_provider_claim_repairs_after_claim_commit_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    ledger = tmp_path / "provider-spend-commit-crash.json"
    monkeypatch.setattr(provider_cost_cap, "caps_from_config", lambda: {"openai": 100.0})
    monkeypatch.setattr(provider_cost_cap, "_shared_world", lambda: None)
    monkeypatch.setattr(provider_cost_cap, "_ledger_path", lambda: ledger)
    service = OutcomeAccounting(
        store=GovernedRecordStore(
            "provider_commit_crash_outcomes", "OCC", "outcome_accounting",
        ),
        reservation_resolver=outcome_module._inspect_provider_reservation,
        reservation_claimer=outcome_module._claim_provider_reservation,
        reservation_committer=outcome_module._commit_provider_reservation,
    )

    with tenant_scope(tenant="customer-one"):
        record = service.admit(
            admission_id="provider-commit-crash", work_item_id="goal:100",
            acceptance_contract_ref="contract:provider-cost:v1",
            owner_id="user:alice", actor="user:alice",
        )
        held = provider_cost_cap.reserve(
            "openai", 2, request_id="provider-commit-crash-call",
            work_item_id="goal:100",
        )
        provider_cost_cap.settle(held, 1)
        reference = provider_cost_cap.reservation_reference(held)
        original_committer = service.reservation_committer

        def crash_before_commit(*_args, **_kwargs):
            raise OSError("simulated crash before provider claim commit")

        service.reservation_committer = crash_before_commit
        request = dict(
            record_id=record["id"], expected_revision=record["revision"],
            operation_id="account-before-commit-crash", actor="system:provider-meter",
            category="inference", attempt_state="succeeded", basis="observed",
            amount=None, currency=None, source_ref=reference,
            source_version="e" * 64, reservation_ref=reference,
        )
        with pytest.raises(OSError, match="simulated crash"):
            service.record_cost(**request)
        appended = service.store.get(record["id"])
        assert len(appended["cost_events"]) == 1
        assert provider_cost_cap.inspect_reservation(
            reference, expected_work_item_id="goal:100",
        ).outcome_claim_state == "prepared"

        service.reservation_committer = original_committer
        repaired = service.record_cost(**request)
        assert repaired["revision"] == appended["revision"]
        assert len(repaired["cost_events"]) == 1
        claim = provider_cost_cap.inspect_reservation(
            reference, expected_work_item_id="goal:100",
        )
        assert claim.outcome_claim_state == "committed"
        assert claim.outcome_claim_event == appended["cost_events"][0]["id"]
