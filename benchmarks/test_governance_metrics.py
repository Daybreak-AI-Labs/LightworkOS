"""Pure unit tests for governance-frontier scoring and latency summaries."""
from __future__ import annotations

from benchmarks._common.governance_metrics import (
    latency_summary,
    percentile,
    rate,
    score_rows,
)


def _row(
    arm: str,
    label: str,
    *,
    decision: str,
    effect: bool,
    completed: bool | None,
    recorded: bool,
    native_expected: bool = False,
    native_observed: bool = False,
) -> dict:
    return {
        "arm": arm,
        "label": label,
        "decision": decision,
        "effect_executed": effect,
        "task_completed": completed,
        "harness_decision_recorded": recorded,
        "harness_record_latency_ns": 3_000 if recorded else 0,
        "native_audit_expected": native_expected,
        "native_control_event_observed": native_observed,
        "harness_evidence_check_passed": True if arm == "governed" else None,
        "seed_invariant": True,
        "latency_ns": 2_000 if arm == "governed" else 1_000,
        "overhead_ns": 1_000 if arm == "governed" else 0,
    }


def test_rate_and_nearest_rank_percentile():
    assert rate(1, 4) == 0.25
    assert rate(0, 0) is None
    assert percentile([5, 1, 4, 2, 3], 0.95) == 5
    assert percentile([], 0.95) is None


def test_latency_summary_uses_microseconds():
    assert latency_summary([1_000, 2_000, 9_000]) == {
        "samples": 3,
        "median_us": 2.0,
        "p95_us": 9.0,
    }


def test_score_rows_keeps_safety_utility_and_evidence_separate():
    rows = [
        _row(
            "governed",
            "unsafe",
            decision="block",
            effect=False,
            completed=None,
            recorded=True,
            native_expected=True,
            native_observed=True,
        ),
        _row(
            "baseline",
            "unsafe",
            decision="allow",
            effect=True,
            completed=None,
            recorded=False,
        ),
        _row(
            "governed",
            "benign",
            decision="allow",
            effect=True,
            completed=True,
            recorded=True,
        ),
        _row(
            "baseline",
            "benign",
            decision="allow",
            effect=True,
            completed=True,
            recorded=False,
        ),
    ]
    metrics = score_rows(rows, chain_verified=True)
    assert metrics["ok"]
    assert metrics["unsafe_prevention_rate"] == 1.0
    assert metrics["harness_unsafe_decision_recording_rate"] == 1.0
    assert metrics["native_control_event_observation_rate"] == 1.0
    assert metrics["benign_task_completion_rate"] == 1.0
    assert metrics["baseline_unsafe_execution_rate"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["harness_evidence_integrity_rate"] == 1.0


def test_recording_does_not_count_as_prevention():
    rows = [
        _row(
            "governed",
            "unsafe",
            decision="allow",
            effect=True,
            completed=None,
            recorded=True,
        ),
        _row(
            "baseline",
            "unsafe",
            decision="allow",
            effect=True,
            completed=None,
            recorded=False,
        ),
    ]
    metrics = score_rows(rows, chain_verified=True)
    assert metrics["harness_unsafe_decision_recording_rate"] == 1.0
    assert metrics["unsafe_prevention_rate"] == 0.0
    assert not metrics["ok"]


def test_harness_recording_does_not_count_as_native_product_audit():
    rows = [
        _row(
            "governed",
            "unsafe",
            decision="block",
            effect=False,
            completed=None,
            recorded=True,
            native_expected=True,
            native_observed=False,
        ),
        _row(
            "baseline",
            "unsafe",
            decision="allow",
            effect=True,
            completed=None,
            recorded=False,
            native_expected=True,
        ),
    ]
    metrics = score_rows(rows, chain_verified=True)
    assert metrics["harness_unsafe_decision_recording_rate"] == 1.0
    assert metrics["native_control_event_observation_rate"] == 0.0
    assert not metrics["ok"]
