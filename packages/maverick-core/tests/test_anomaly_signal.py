from __future__ import annotations

from maverick.anomaly_signal import SIGNAL_SCHEMA
from maverick.cross_run_anomaly import Anomaly
from maverick.cross_run_anomaly import to_signal as run_to_signal
from maverick.finance.anomaly_engine import (
    FinanceAnomalyConfig,
    FinanceTransaction,
    finding_to_signal,
    scan_transactions,
)


def test_run_and_finance_detectors_share_stable_signal_contract():
    run_signal = run_to_signal(
        42,
        Anomaly("novel_event_kind", "high", "run #42 emitted an unseen tool event"),
    )
    report = scan_transactions([
        FinanceTransaction(
            transaction_id="off-hours-1",
            amount="12.34",
            currency="USD",
            posted_at="2026-07-22T03:00:00Z",
            source_system="erp-gl",
            source_record_id="journal/1",
        )
    ], config=FinanceAnomalyConfig())
    finance_signal = finding_to_signal(report.findings[0])

    assert run_signal.schema == finance_signal.schema == SIGNAL_SCHEMA
    assert run_signal.subject_ref == "goal:42"
    assert finance_signal.subject_ref == report.findings[0].finding_id
    assert len(run_signal.evidence_sha256s[0]) == 64
    assert finance_signal.evidence_sha256s == (
        report.findings[0].evidence[0]["normalized_record_sha256"],
    )
    assert run_signal.fingerprint == run_to_signal(
        42,
        Anomaly("novel_event_kind", "high", "run #42 emitted an unseen tool event"),
    ).fingerprint
