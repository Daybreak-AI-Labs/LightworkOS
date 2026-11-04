"""Tail-latency hunting: flag fat-tailed tools by p99/p50 ratio."""
from __future__ import annotations

from maverick import tail_latency as tl


def _row(tool, count, p50, p99):
    return {"tool": tool, "count": count, "p50_ms": p50, "p99_ms": p99}


def test_flags_high_tail_ratio():
    report = [
        _row("fast", 100, 10.0, 12.0),    # ratio 1.2 -> fine
        _row("spiky", 100, 10.0, 80.0),   # ratio 8.0 -> flagged
    ]
    out = tl.hunt(report, ratio_threshold=3.0, min_count=20)
    assert [r["tool"] for r in out] == ["spiky"]
    assert out[0]["tail_ratio"] == 8.0
    assert out[0]["tail_gap_ms"] == 70.0


def test_min_count_filter():
    report = [_row("rare", 5, 10.0, 100.0)]  # huge ratio but too few samples
    assert tl.hunt(report, min_count=20) == []


def test_zero_p50_skipped():
    report = [_row("weird", 100, 0.0, 50.0)]
    assert tl.hunt(report) == []


def test_sorted_by_ratio_desc():
    report = [
        _row("a", 50, 10.0, 40.0),    # 4.0
        _row("b", 50, 10.0, 90.0),    # 9.0
        _row("c", 50, 10.0, 60.0),    # 6.0
    ]
    out = tl.hunt(report, ratio_threshold=3.0, min_count=20)
    assert [r["tool"] for r in out] == ["b", "c", "a"]


def test_threshold_respected():
    report = [_row("borderline", 100, 10.0, 25.0)]  # ratio 2.5
    assert tl.hunt(report, ratio_threshold=3.0) == []
    assert len(tl.hunt(report, ratio_threshold=2.0)) == 1


def test_hunt_over_live_report_is_empty_by_default():
    # hunt() with no report reads the live tool_latency samples. Reset them
    # first so this test is hermetic: in the full suite other tests record
    # tool latencies into that module global, so without the reset this
    # order-dependently sees a non-empty live report and fails.
    from maverick import tool_latency
    tool_latency.reset()
    assert tl.hunt() == []
