"""Tests for continuous group-fairness monitoring: the structured metric math,
the rolling-window accumulation, and the breach/drift alerting with an injected
audit sink."""
from __future__ import annotations

from maverick import fairness_monitor as fm


class TestComputeMetrics:
    def test_adverse_impact_fails_four_fifths(self):
        counts = {"A": {"selected": 5, "total": 5}, "B": {"selected": 1, "total": 5}}
        m = fm.compute_metrics(counts)
        assert m.rates["A"] == 1.0 and m.rates["B"] == 0.2
        assert m.impact_ratios["B"] == 0.2
        assert m.min_impact_ratio == 0.2
        assert m.failing_groups == ["B"] and not m.passed
        assert m.demographic_parity_diff == 0.8
        assert m.samples == 10

    def test_passing_group_set(self):
        counts = {"A": {"selected": 4, "total": 5}, "B": {"selected": 5, "total": 5}}
        m = fm.compute_metrics(counts)  # impact A = 0.8 == threshold -> not failing
        assert m.passed and m.failing_groups == []
        assert m.min_impact_ratio == 0.8

    def test_equal_opportunity_difference(self):
        counts = {
            "A": {"selected": 8, "total": 10, "positives": 5, "tp": 4},
            "B": {"selected": 9, "total": 10, "positives": 5, "tp": 5},
        }
        m = fm.compute_metrics(counts)
        assert round(m.equal_opportunity_diff, 6) == 0.2  # TPR 0.8 vs 1.0

    def test_single_group_returns_none(self):
        assert fm.compute_metrics({"A": {"selected": 1, "total": 2}}) is None

    def test_out_of_range_counts_are_clamped_not_raised(self):
        counts = {"A": {"selected": 99, "total": 10}, "B": {"selected": -3, "total": 10}}
        m = fm.compute_metrics(counts)
        assert m.rates["A"] == 1.0 and m.rates["B"] == 0.0

    def test_custom_threshold(self):
        counts = {"A": {"selected": 7, "total": 10}, "B": {"selected": 10, "total": 10}}
        # impact A = 0.7: fails at 0.8, passes at 0.6
        assert not fm.compute_metrics(counts, threshold=0.8).passed
        assert fm.compute_metrics(counts, threshold=0.6).passed


class TestMonitorWindow:
    def test_evaluate_none_below_min_samples(self):
        mon = fm.FairnessMonitor(min_samples=4)
        mon.record("A", True)
        mon.record("B", False)
        assert mon.evaluate() is None  # only 2 < 4

    def test_record_batch_tuples_and_evaluate(self):
        mon = fm.FairnessMonitor(min_samples=4)
        mon.record_batch([("A", True), ("A", True), ("B", False), ("B", True)])
        m = mon.evaluate()
        assert m is not None
        assert m.rates["A"] == 1.0 and m.rates["B"] == 0.5

    def test_rolling_window_drops_oldest(self):
        mon = fm.FairnessMonitor(min_samples=2, window=4)
        # 4 "A True" then 4 "B False" evicts all A; only B remains in the window,
        # so with a single group there is no disparity to measure -> None.
        mon.record_batch([("A", True)] * 4)
        mon.record_batch([("B", False)] * 4)
        assert mon.evaluate() is None

    def test_window_keeps_recent_mix(self):
        mon = fm.FairnessMonitor(min_samples=2, window=4)
        mon.record_batch([("A", True), ("A", True), ("B", False), ("B", False)])
        m = mon.evaluate()
        assert set(m.rates) == {"A", "B"} and m.rates["B"] == 0.0

    def test_positive_label_feeds_equal_opportunity(self):
        mon = fm.FairnessMonitor(min_samples=4)
        mon.record_batch([
            ("A", True, True), ("A", False, True),   # A: 1/2 TPR
            ("B", True, True), ("B", True, True),     # B: 2/2 TPR
        ])
        m = mon.evaluate()
        assert m.equal_opportunity_diff == 0.5


class TestMonitorAlerting:
    def test_healthy_check_sets_baseline_and_returns_none(self):
        mon = fm.FairnessMonitor(min_samples=4)
        mon.record_batch([("A", True)] * 4 + [("B", True)] * 4)  # both 1.0
        assert mon.check() is None
        assert mon.baseline_min_ratio == 1.0

    def test_adverse_impact_raises_alert_and_records(self):
        seen = []
        mon = fm.FairnessMonitor(min_samples=4, audit_sink=lambda a: seen.append(a) or True)
        mon.record_batch([("A", True)] * 5 + [("B", False)] * 5)
        alert = mon.check()
        assert alert is not None
        assert alert.reason == "adverse_impact"
        assert alert.recorded is True and seen and seen[0] is alert

    def test_drift_raises_alert_when_ratio_falls_below_baseline(self):
        mon = fm.FairnessMonitor(min_samples=4, drift_tolerance=0.1)
        mon.set_baseline(1.0)
        # A 17/20 = 0.85 impact (passes four-fifths) but 1.0 - 0.85 = 0.15 > 0.1
        mon.record_batch([("A", True)] * 17 + [("A", False)] * 3 + [("B", True)] * 20)
        alert = mon.check()
        assert alert is not None and alert.reason == "drift"
        assert alert.metrics.passed  # not an adverse-impact failure, pure drift

    def test_both_reasons_combine(self):
        mon = fm.FairnessMonitor(min_samples=4, drift_tolerance=0.1)
        mon.set_baseline(1.0)
        mon.record_batch([("A", False)] * 10 + [("B", True)] * 10)  # impact A = 0.0
        alert = mon.check()
        assert alert.reason == "adverse_impact+drift"

    def test_audit_sink_exception_is_swallowed(self):
        def boom(_a):
            raise RuntimeError("audit down")

        mon = fm.FairnessMonitor(min_samples=4, audit_sink=boom)
        mon.record_batch([("A", True)] * 5 + [("B", False)] * 5)
        alert = mon.check()  # must not raise
        assert alert is not None and alert.recorded is False

    def test_set_baseline_from_current(self):
        mon = fm.FairnessMonitor(min_samples=4)
        mon.record_batch([("A", True)] * 4 + [("B", False)] * 4)  # min impact 0.0
        assert mon.set_baseline() == 0.0


def test_metrics_report_is_schemad_and_evidence_ready():
    from maverick.fairness_monitor import (
        FAIRNESS_REPORT_SCHEMA,
        metrics_report,
    )

    counts = {
        "group_a": {"selected": 8, "total": 10},
        "group_b": {"selected": 4, "total": 10},
    }
    report = metrics_report(counts)
    assert report["schema"] == FAIRNESS_REPORT_SCHEMA
    assert report["min_impact_ratio"] == 0.5
    assert report["failing_groups"] == ["group_b"]
    assert report["passed"] is False
    assert report["samples"] == 20
    # One populated group: no disparity to measure, no report.
    assert metrics_report({"only": {"selected": 1, "total": 2}}) is None
