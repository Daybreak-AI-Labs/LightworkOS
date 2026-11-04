"""Extended per-tool latency stats."""
from __future__ import annotations

from maverick import tool_latency


def test_extended_report_moments():
    tool_latency.reset()
    for ms in (10, 20, 30, 40, 100):
        tool_latency.record("t", ms)
    rep = {r["tool"]: r for r in tool_latency.extended_report()}["t"]
    assert rep["count"] == 5
    assert rep["min_ms"] == 10
    assert rep["max_ms"] == 100
    assert rep["mean_ms"] == 40.0  # (10+20+30+40+100)/5
    assert rep["stdev_ms"] > 0
    assert rep["p50_ms"] == 30
    assert "p90_ms" in rep
    tool_latency.reset()


def test_extended_report_single_sample_zero_stdev():
    tool_latency.reset()
    tool_latency.record("solo", 42)
    rep = tool_latency.extended_report()[0]
    assert rep["stdev_ms"] == 0.0
    assert rep["mean_ms"] == 42.0
    tool_latency.reset()


def test_extended_report_empty():
    tool_latency.reset()
    assert tool_latency.extended_report() == []


def test_report_still_works():
    # the original report() shape is unchanged (additive feature)
    tool_latency.reset()
    tool_latency.record("x", 5)
    row = tool_latency.report()[0]
    assert set(row) == {"tool", "count", "p50_ms", "p95_ms", "p99_ms", "max_ms"}
    tool_latency.reset()
