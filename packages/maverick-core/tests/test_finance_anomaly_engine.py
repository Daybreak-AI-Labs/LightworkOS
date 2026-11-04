"""Deterministic finance anomaly rules and governed case lifecycle."""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, time, timezone
from decimal import Decimal

import pytest
from maverick import governed_records
from maverick.finance import anomaly_engine
from maverick.finance.anomaly_engine import (
    BENFORD_RULE_ID,
    DUPLICATE_RULE_ID,
    JUST_UNDER_RULE_ID,
    OFF_HOURS_RULE_ID,
    SPLIT_PAYMENT_RULE_ID,
    ApprovalThreshold,
    FinanceAnomalyCaseQueue,
    FinanceAnomalyConfig,
    FinanceAnomalyInputLimit,
    FinanceAnomalyStateError,
    FinanceTransaction,
    FourEyesRequired,
    scan_transactions,
)
from maverick.privacy_ops import RecordConflict


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    governed_records._reset_process_authority_pin_for_testing()
    yield
    governed_records._reset_process_authority_pin_for_testing()


def _transaction(
    transaction_id: str,
    amount: object,
    posted_at: str,
    *,
    counterparty: str = "vendor-1",
    invoice: str = "",
    reference: str = "",
    currency: str = "USD",
) -> FinanceTransaction:
    source_digest = hashlib.sha256(f"source:{transaction_id}".encode()).hexdigest()
    return FinanceTransaction(
        transaction_id=transaction_id,
        amount=Decimal(str(amount)),
        currency=currency,
        posted_at=posted_at,
        source_system="erp-ap",
        source_record_id=f"ap/{transaction_id}",
        counterparty_id=counterparty,
        invoice_id=invoice,
        reference=reference,
        source_uri=f"erp://payments/{transaction_id}",
        source_sha256=source_digest,
    )


def test_anomaly_gate_obeys_effective_kill_switch(tmp_path):
    from maverick import config

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[finance_operations]\nenable = true\nanomaly_enable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert anomaly_engine.enabled() is True

    config_path.write_text(
        "[finance_operations]\nenable = true\nanomaly_enable = false\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert anomaly_engine.enabled() is False


def _evaluation(report, rule_id):
    return next(item for item in report.evaluations if item.rule_id == rule_id)


class _MemoryCaseStore:
    """Small governed-store double for pagination above the local file ceiling."""

    backend_kind = "local"

    def __init__(self):
        self.rows = {}
        self.clock = 1_700_000_000.0

    def authoritative_time(self):
        self.clock += 0.001
        return self.clock

    def get(self, record_id):
        row = self.rows.get(record_id)
        return None if row is None else copy.deepcopy(row)

    def create(self, record, *, action, actor):
        assert action and actor
        value = copy.deepcopy(record)
        value.update(
            revision=1,
            created_at=self.clock,
            updated_at=self.clock,
        )
        if value["id"] in self.rows:
            raise RecordConflict("record exists")
        self.rows[value["id"]] = value
        return copy.deepcopy(value)

    def update(self, record_id, mutate, *, expected_revision, action, actor):
        assert action and actor
        current = self.get(record_id)
        if current is None:
            return None
        if current["revision"] != expected_revision:
            raise RecordConflict("stale revision")
        mutate(current)
        current["revision"] += 1
        current["updated_at"] = self.clock
        self.rows[record_id] = current
        return copy.deepcopy(current)

    def list(self, *, limit=None):
        rows = [copy.deepcopy(self.rows[key]) for key in sorted(self.rows)]
        return rows if limit is None else rows[:limit]

    def iter_record_ids(self, *, start_after="", limit=100):
        identifiers = sorted(self.rows)
        pivot = next(
            (
                index
                for index, identifier in enumerate(identifiers)
                if identifier > start_after
            ),
            len(identifiers),
        )
        for identifier in (identifiers[pivot:] + identifiers[:pivot])[:limit]:
            yield identifier, identifier


def test_duplicate_finding_is_stable_and_carries_exact_provenance():
    first = _transaction("tx-001", "1250.00", "2026-07-20T14:00:00Z", invoice="INV-9")
    second = _transaction("tx-002", "1250", "2026-07-21T14:00:00Z", invoice="inv-9")

    report = scan_transactions([first, second])
    reordered = scan_transactions([second, first])

    duplicate = next(item for item in report.findings if item.rule_id == DUPLICATE_RULE_ID)
    assert duplicate.finding_id == next(
        item.finding_id for item in reordered.findings if item.rule_id == DUPLICATE_RULE_ID
    )
    assert duplicate.severity == "high" and duplicate.score == 97
    assert [item["transaction_id"] for item in duplicate.evidence] == ["tx-001", "tx-002"]
    for evidence in duplicate.evidence:
        provenance = evidence["provenance"]
        assert provenance["source_system"] == "erp-ap"
        assert provenance["source_record_id"].startswith("ap/")
        assert len(provenance["source_sha256"]) == 64
        body = {key: value for key, value in evidence.items() if key != "normalized_record_sha256"}
        digest = hashlib.sha256(
            json.dumps(
                body,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()
        assert evidence["normalized_record_sha256"] == digest
    assert _evaluation(report, DUPLICATE_RULE_ID).status == "finding"
    assert "not evidence of fraud" in duplicate.notice
    assert report.input_sha256 == reordered.input_sha256
    assert report.config_sha256 == reordered.config_sha256
    assert report.scan_sha256 == reordered.scan_sha256
    assert report.config["duplicate_window_hours"] == 72


def test_scan_receipt_binds_rule_configuration_even_when_inputs_are_identical():
    rows = [
        _transaction("receipt-a", 42, "2026-07-20T12:00:00Z"),
        _transaction("receipt-b", 42, "2026-07-20T13:00:00Z"),
    ]

    short = scan_transactions(
        rows,
        config=FinanceAnomalyConfig(duplicate_window_hours=2),
    )
    long = scan_transactions(
        rows,
        config=FinanceAnomalyConfig(duplicate_window_hours=72),
    )

    assert short.input_sha256 == long.input_sha256
    assert short.config_sha256 != long.config_sha256
    assert short.scan_sha256 != long.scan_sha256
    assert short.config["duplicate_window_hours"] == 2


def test_scan_rejects_oversized_finding_and_report_before_persistence(monkeypatch):
    rows = [
        _transaction("bounded-a", 42, "2026-07-20T12:00:00Z"),
        _transaction("bounded-b", 42, "2026-07-20T13:00:00Z"),
    ]
    normal = scan_transactions(rows)
    finding = next(
        item for item in normal.findings if item.rule_id == DUPLICATE_RULE_ID
    )

    monkeypatch.setattr(anomaly_engine, "_MAX_FINDING_JSON_BYTES", 512)
    with pytest.raises(FinanceAnomalyInputLimit, match="finding exceeds"):
        scan_transactions(rows)
    with pytest.raises(FinanceAnomalyInputLimit, match="governed case"):
        FinanceAnomalyCaseQueue().enqueue(finding, opened_by="analyst")
    assert FinanceAnomalyCaseQueue().list_cases() == []

    monkeypatch.setattr(anomaly_engine, "_MAX_FINDING_JSON_BYTES", 4 * 1024 * 1024)
    monkeypatch.setattr(anomaly_engine, "_MAX_REPORT_JSON_BYTES", 512)
    with pytest.raises(FinanceAnomalyInputLimit, match="scan report exceeds"):
        scan_transactions(rows)


def test_duplicate_without_reference_is_lower_confidence_and_time_bounded():
    rows = [
        _transaction("a", 42, "2026-07-20T12:00:00Z"),
        _transaction("b", 42, "2026-07-20T13:00:00Z"),
        _transaction("c", 42, "2026-08-20T13:00:00Z"),
    ]
    report = scan_transactions(rows, config=FinanceAnomalyConfig(duplicate_window_hours=2))
    duplicates = [item for item in report.findings if item.rule_id == DUPLICATE_RULE_ID]
    assert len(duplicates) == 1
    assert duplicates[0].severity == "medium"
    assert [item["transaction_id"] for item in duplicates[0].evidence] == ["a", "b"]


def test_benford_requires_explicit_eligibility_and_minimum_sample():
    rows = [
        _transaction(f"tx-{index}", index + 1, "2026-07-20T14:00:00Z", counterparty="")
        for index in range(60)
    ]
    default_report = scan_transactions(rows)
    assert _evaluation(default_report, BENFORD_RULE_ID).status == "ineligible"
    assert not any(item.rule_id == BENFORD_RULE_ID for item in default_report.findings)

    eligible = scan_transactions(
        rows,
        config=FinanceAnomalyConfig(
            benford_population_eligible=True,
            benford_min_sample=100,
        ),
    )
    evaluation = _evaluation(eligible, BENFORD_RULE_ID)
    assert evaluation.status == "insufficient_sample"
    assert evaluation.sample_size == 60
    assert "not transaction-level proof" in " ".join(evaluation.caveats)


def test_benford_biased_population_flags_with_full_manifest():
    rows = []
    for index in range(120):
        amount = Decimal(9) * (Decimal(10) ** (index % 3))
        rows.append(
            _transaction(
                f"ben-{index:03d}",
                amount,
                "2026-07-20T14:00:00Z",
                counterparty="",
            )
        )
    report = scan_transactions(
        rows,
        config=FinanceAnomalyConfig(benford_population_eligible=True),
    )
    finding = next(item for item in report.findings if item.rule_id == BENFORD_RULE_ID)
    assert finding.severity == "high"
    assert len(finding.evidence) == 120
    assert finding.metrics["digit_counts"]["9"] == 120
    assert finding.metrics["population_eligibility_attested"] is True
    assert _evaluation(report, BENFORD_RULE_ID).status == "finding"


def test_benford_rejects_population_without_order_of_magnitude_span():
    rows = [
        _transaction(
            f"narrow-{index}",
            100 + index,
            "2026-07-20T14:00:00Z",
            counterparty="",
        )
        for index in range(100)
    ]
    report = scan_transactions(
        rows,
        config=FinanceAnomalyConfig(benford_population_eligible=True),
    )
    evaluation = _evaluation(report, BENFORD_RULE_ID)
    assert evaluation.status == "ineligible"
    assert "spans 1 decimal order" in evaluation.explanation


def test_benford_never_combines_currencies_to_reach_sample_floor():
    rows = [
        _transaction(
            f"usd-{index}",
            Decimal(9) * (Decimal(10) ** (index % 3)),
            "2026-07-20T14:00:00Z",
            counterparty="",
            currency="USD",
        )
        for index in range(60)
    ] + [
        _transaction(
            f"eur-{index}",
            Decimal(9) * (Decimal(10) ** (index % 3)),
            "2026-07-20T14:00:00Z",
            counterparty="",
            currency="EUR",
        )
        for index in range(60)
    ]
    report = scan_transactions(
        rows,
        config=FinanceAnomalyConfig(benford_population_eligible=True),
    )
    evaluation = _evaluation(report, BENFORD_RULE_ID)
    assert evaluation.status == "insufficient_sample"
    assert evaluation.sample_size == 120
    assert "2 insufficient_sample" in evaluation.explanation
    assert not any(item.rule_id == BENFORD_RULE_ID for item in report.findings)


def test_approval_limit_rules_find_just_under_and_split_payments():
    threshold = ApprovalThreshold(
        "ap-approval-10k",
        "USD",
        Decimal("10000"),
        "policy://delegation-of-authority/v4#ap-10k",
    )
    rows = [
        _transaction("near", 9900, "2026-07-20T12:00:00Z", counterparty="vendor-near"),
        _transaction("split-a", 6000, "2026-07-20T13:00:00Z", counterparty="vendor-split"),
        _transaction("split-b", 4500, "2026-07-20T14:00:00Z", counterparty="vendor-split"),
    ]
    report = scan_transactions(
        rows,
        config=FinanceAnomalyConfig(approval_thresholds=(threshold,)),
    )
    near = next(item for item in report.findings if item.rule_id == JUST_UNDER_RULE_ID)
    split = next(item for item in report.findings if item.rule_id == SPLIT_PAYMENT_RULE_ID)
    assert near.evidence[0]["transaction_id"] == "near"
    assert near.metrics["policy_ref"].endswith("#ap-10k")
    assert split.severity == "high"
    assert split.metrics["aggregate_amount"] == "10500"
    assert {item["transaction_id"] for item in split.evidence} == {"split-a", "split-b"}
    assert _evaluation(report, JUST_UNDER_RULE_ID).status == "finding"
    assert _evaluation(report, SPLIT_PAYMENT_RULE_ID).status == "finding"


def test_approval_limit_rules_are_explicitly_disabled_without_policy_limits():
    report = scan_transactions([_transaction("tx", 9999, "2026-07-20T14:00:00Z")])
    assert _evaluation(report, JUST_UNDER_RULE_ID).status == "disabled"
    assert _evaluation(report, SPLIT_PAYMENT_RULE_ID).status == "disabled"


def test_off_hours_uses_configured_timezone_and_calendar():
    saturday = _transaction("weekend", 100, "2026-07-18T16:00:00Z")
    overnight = _transaction("overnight", 100, "2026-07-20T07:30:00Z")
    business = _transaction("business", 100, "2026-07-20T16:00:00Z")
    report = scan_transactions(
        [business, saturday, overnight],
        config=FinanceAnomalyConfig(
            business_timezone="America/New_York",
            business_start=time(8),
            business_end=time(18),
        ),
    )
    findings = [item for item in report.findings if item.rule_id == OFF_HOURS_RULE_ID]
    assert {item.evidence[0]["transaction_id"] for item in findings} == {
        "weekend",
        "overnight",
    }
    by_id = {item.evidence[0]["transaction_id"]: item for item in findings}
    assert by_id["overnight"].metrics["local_posted_at"].startswith("2026-07-20T03:30")
    assert by_id["overnight"].severity == "medium"


def test_scan_enforces_input_identity_and_output_bounds():
    with pytest.raises(FinanceAnomalyInputLimit, match="2-transaction bound"):
        scan_transactions(
            [
                _transaction("a", 1, "2026-07-20T02:00:00Z"),
                _transaction("b", 2, "2026-07-20T02:00:00Z"),
                _transaction("c", 3, "2026-07-20T02:00:00Z"),
            ],
            config=FinanceAnomalyConfig(max_transactions=2),
        )
    duplicate_id = _transaction("same", 1, "2026-07-20T14:00:00Z")
    with pytest.raises(ValueError, match="transaction_id values must be unique"):
        scan_transactions([duplicate_id, duplicate_id])

    report = scan_transactions(
        [
            _transaction("a", 1, "2026-07-20T02:00:00Z", counterparty="a"),
            _transaction("b", 2, "2026-07-20T02:00:00Z", counterparty="b"),
        ],
        config=FinanceAnomalyConfig(max_findings=1),
    )
    assert report.truncated is True and report.omitted_findings == 1
    assert len(report.findings) == 1


def test_scan_retains_top_findings_without_materializing_threshold_candidate_flood(
    monkeypatch,
):
    thresholds = tuple(
        ApprovalThreshold(
            f"threshold-{index:03d}",
            "USD",
            Decimal("100"),
            f"policy://approval/v1#threshold-{index:03d}",
        )
        for index in range(128)
    )
    rows = [
        _transaction(
            f"scale-{index:04d}",
            99,
            "2026-07-20T14:00:00Z",
            counterparty="scale-vendor",
        )
        for index in range(1_000)
    ]
    materialized = 0
    original = anomaly_engine._FindingSeed.materialize

    def _materialize(seed):
        nonlocal materialized
        materialized += 1
        return original(seed)

    monkeypatch.setattr(anomaly_engine._FindingSeed, "materialize", _materialize)
    report = scan_transactions(
        reversed(rows),
        config=FinanceAnomalyConfig(
            max_transactions=1_000,
            max_findings=7,
            approval_thresholds=thresholds,
        ),
    )

    # 128,000 just-under candidates + 64,000 disjoint split candidates + one
    # unreferenced duplicate group.  Business-hour rows do not flag off-hours.
    assert sum(item.finding_count for item in report.evaluations) == 192_001
    assert report.omitted_findings == 191_994
    assert report.truncated is True
    assert len(report.findings) == materialized == 7
    assert all(item.rule_id == SPLIT_PAYMENT_RULE_ID for item in report.findings)
    assert [item.finding_id for item in report.findings] == sorted(
        item.finding_id for item in report.findings
    )


def test_scan_rejects_threshold_work_above_cpu_budget_before_detection(monkeypatch):
    thresholds = tuple(
        ApprovalThreshold(
            f"threshold-{index:03d}",
            "USD",
            Decimal("100"),
            f"policy://approval/v1#threshold-{index:03d}",
        )
        for index in range(128)
    )
    rows = [
        _transaction(
            f"cpu-bound-{index:04d}",
            99,
            "2026-07-20T14:00:00Z",
            counterparty="scale-vendor",
        )
        for index in range(2_000)
    ]
    called = False

    def _unexpected_detector(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("detector must not run above the threshold work budget")

    monkeypatch.setattr(anomaly_engine, "_benford_findings", _unexpected_detector)
    with pytest.raises(FinanceAnomalyInputLimit, match="approval-threshold work budget"):
        scan_transactions(
            rows,
            config=FinanceAnomalyConfig(
                max_transactions=2_000,
                approval_thresholds=thresholds,
            ),
        )
    assert called is False


def test_mapping_input_requires_aware_time_and_source_provenance():
    with pytest.raises(ValueError, match="timezone offset"):
        FinanceTransaction.from_mapping(
            {
                "id": "tx",
                "amount": "10",
                "currency": "USD",
                "timestamp": "2026-07-20T10:00:00",
                "provenance": {"source_system": "erp", "source_record_id": "1"},
            }
        )
    transaction = FinanceTransaction.from_mapping(
        {
            "id": "tx",
            "amount": "10",
            "currency": "usd",
            "timestamp": "2026-07-20T10:00:00-04:00",
            "vendor_id": "v-1",
            "provenance": {"source_system": "erp", "source_record_id": "row-1"},
        }
    )
    assert transaction.posted_at == datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    assert transaction.currency == "USD"


def test_governed_case_queue_is_idempotent_cas_and_four_eyes():
    report = scan_transactions(
        [
            _transaction("dup-a", 500, "2026-07-20T14:00:00Z", invoice="INV-1"),
            _transaction("dup-b", 500, "2026-07-20T15:00:00Z", invoice="INV-1"),
        ]
    )
    finding = next(item for item in report.findings if item.rule_id == DUPLICATE_RULE_ID)
    queue = FinanceAnomalyCaseQueue()
    opened = queue.enqueue(finding, opened_by="case-intake-reviewer")
    assert opened["revision"] == 1 and opened["status"] == "open"
    assert queue.enqueue(finding, opened_by="another-intake") == opened

    disposed = queue.record_disposition(
        opened["id"],
        outcome="confirmed",
        rationale="The payment register confirms both records were released.",
        human_actor="fraud-investigator",
        expected_revision=opened["revision"],
    )
    assert disposed["revision"] == 2 and disposed["status"] == "dispositioned"
    with pytest.raises(FourEyesRequired, match="different human"):
        queue.close_case(
            opened["id"],
            rationale="Investigation complete.",
            human_actor="fraud-investigator",
            expected_revision=disposed["revision"],
        )
    assert queue.get(opened["id"])["revision"] == 2
    with pytest.raises(RecordConflict):
        queue.close_case(
            opened["id"],
            rationale="Independent review complete.",
            human_actor="control-owner",
            expected_revision=1,
        )

    closed = queue.close_case(
        opened["id"],
        rationale="Independent reviewer verified evidence and disposition.",
        human_actor="control-owner",
        expected_revision=disposed["revision"],
    )
    assert closed["revision"] == 3 and closed["status"] == "closed"
    assert closed["closure"]["four_eyes_satisfied"] is True
    assert closed["closure"]["closed_by"] != closed["closure"]["disposition_actor"]
    restarted = FinanceAnomalyCaseQueue()
    assert restarted.get(opened["id"])["revision"] == 3
    assert [item["id"] for item in restarted.list_cases(status="closed")] == [opened["id"]]


def test_case_queue_pages_more_than_five_thousand_with_status_filtering():
    rows = [
        _transaction(
            f"page-{index:04d}",
            index + 1,
            "2026-07-20T03:00:00Z",
            counterparty=f"vendor-{index:04d}",
        )
        for index in range(5_001)
    ]
    report = scan_transactions(
        rows,
        config=FinanceAnomalyConfig(
            max_transactions=5_001,
            max_findings=5_001,
        ),
    )
    assert len(report.findings) == 5_001
    store = _MemoryCaseStore()
    queue = FinanceAnomalyCaseQueue(store=store)
    for finding in report.findings:
        queue.enqueue(finding, opened_by="case-intake-reviewer")

    in_review_ids = sorted(store.rows)[:17]
    for case_id in in_review_ids:
        queue.record_disposition(
            case_id,
            outcome="needs_information",
            rationale="Obtain supporting close-window evidence.",
            human_actor="investigator",
            expected_revision=1,
        )

    assert len(queue.list_cases(limit=20)) == 20
    discovered = []
    cursor = None
    while True:
        page = queue.list_case_page(
            status="in_review",
            limit=5,
            cursor=cursor,
        )
        discovered.extend(row["id"] for row in page.cases)
        if not page.has_more:
            break
        assert page.next_cursor
        cursor = page.next_cursor
    assert discovered == in_review_ids

    all_ids = []
    cursor = None
    while True:
        page = queue.list_case_page(limit=777, cursor=cursor)
        all_ids.extend(row["id"] for row in page.cases)
        if not page.has_more:
            break
        cursor = page.next_cursor
    assert all_ids == sorted(store.rows)
    assert len(all_ids) == 5_001
    assert len(set(all_ids)) == 5_001

    with pytest.raises(ValueError, match="cursor is invalid"):
        queue.list_case_page(cursor="not-a-valid-cursor")


def test_case_queue_rejects_tampered_normalized_evidence():
    finding = next(
        item
        for item in scan_transactions(
            [_transaction("late", 10, "2026-07-20T03:00:00Z")]
        ).findings
        if item.rule_id == OFF_HOURS_RULE_ID
    )
    finding.evidence[0]["amount"] = "11"
    with pytest.raises(FinanceAnomalyStateError, match="evidence digest is inconsistent"):
        FinanceAnomalyCaseQueue().enqueue(finding, opened_by="intake-reviewer")


def test_case_summary_projection_is_read_bounded_and_omits_finding_evidence():
    report = scan_transactions([
        _transaction(f"summary-{index}", index + 1, "2026-07-20T03:00:00Z")
        for index in range(3)
    ])
    store = _MemoryCaseStore()
    queue = FinanceAnomalyCaseQueue(store=store)
    for finding in report.findings:
        queue.enqueue(finding, opened_by="case-intake-reviewer")

    reads = 0
    original_get = store.get

    def _counted_get(record_id):
        nonlocal reads
        reads += 1
        return original_get(record_id)

    store.get = _counted_get
    summary = queue.case_status_summary(scan_limit=2)
    assert summary["record_reads"] == 2
    assert summary["truncated"] is True
    assert reads == 2

    reads = 0
    page = queue.list_case_summary_page(limit=1)
    assert reads == 1
    assert page.has_more is True
    assert "finding" not in page.cases[0]
    assert "disposition_history" not in page.cases[0]


def test_case_needs_final_disposition_and_closed_cases_are_immutable():
    transaction = _transaction("late", 10, "2026-07-20T03:00:00Z")
    finding = next(
        item for item in scan_transactions([transaction]).findings if item.rule_id == OFF_HOURS_RULE_ID
    )
    queue = FinanceAnomalyCaseQueue()
    opened = queue.enqueue(finding, opened_by="intake-reviewer")
    pending = queue.record_disposition(
        opened["id"],
        outcome="needs_information",
        rationale="Obtain the approved accounting-close window.",
        human_actor="investigator",
        expected_revision=opened["revision"],
    )
    assert pending["status"] == "in_review"
    with pytest.raises(FinanceAnomalyStateError, match="final human disposition"):
        queue.close_case(
            opened["id"],
            rationale="Not ready to close.",
            human_actor="investigator",
            expected_revision=pending["revision"],
        )
    final = queue.record_disposition(
        opened["id"],
        outcome="false_positive",
        rationale="The controller supplied the approved close-window record.",
        human_actor="investigator",
        expected_revision=pending["revision"],
    )
    closed = queue.close_case(
        opened["id"],
        rationale="Disposition evidence is complete.",
        human_actor="investigator",
        expected_revision=final["revision"],
    )
    assert closed["closure"]["four_eyes_required"] is False
    with pytest.raises(FinanceAnomalyStateError, match="immutable"):
        queue.record_disposition(
            opened["id"],
            outcome="confirmed",
            rationale="Attempted post-closure mutation.",
            human_actor="investigator",
            expected_revision=closed["revision"],
        )
