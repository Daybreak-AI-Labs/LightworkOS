"""Per-tool latency profile."""
from __future__ import annotations

import asyncio

from maverick import tool_latency
from maverick.tools import Tool, ToolRegistry


def test_record_report_reset():
    tool_latency.reset()
    for ms in (10, 20, 30, 40, 100):
        tool_latency.record("t", ms)
    tool_latency.record("t", -5)   # negative ignored
    tool_latency.record("t", None)  # None ignored
    rep = {r["tool"]: r for r in tool_latency.report()}
    assert rep["t"]["count"] == 5
    assert rep["t"]["max_ms"] == 100
    assert rep["t"]["p50_ms"] == 30  # nearest-rank median of [10,20,30,40,100]
    tool_latency.reset()
    assert tool_latency.report() == []


def test_report_sorted_by_p95_desc():
    tool_latency.reset()
    tool_latency.record("fast", 1)
    tool_latency.record("slow", 500)
    rep = tool_latency.report()
    assert rep[0]["tool"] == "slow" and rep[-1]["tool"] == "fast"
    tool_latency.reset()


def test_ring_buffer_is_bounded():
    tool_latency.reset()


def test_distinct_tool_series_are_bounded(monkeypatch):
    tool_latency.reset()
    monkeypatch.setattr(tool_latency, "_MAX_TOOLS", 4)
    for index in range(20):
        tool_latency.record(f"generated-{index}", index)
    rows = {row["tool"]: row for row in tool_latency.report()}
    assert len(rows) == 4
    assert rows[tool_latency._OVERFLOW_TOOL]["count"] == 17
    tool_latency.reset()
    for i in range(tool_latency._MAX_SAMPLES + 500):
        tool_latency.record("flood", i)
    rep = {r["tool"]: r for r in tool_latency.report()}
    assert rep["flood"]["count"] == tool_latency._MAX_SAMPLES  # capped, memory flat
    tool_latency.reset()


def _reg(name, fn):
    reg = ToolRegistry()
    reg.register(Tool(name=name, description="d",
                      input_schema={"type": "object"}, fn=fn))
    return reg


def test_run_records_latency_on_success():
    tool_latency.reset()
    out = asyncio.run(_reg("ping", lambda args: "pong").run("ping", {}))
    assert out == "pong"
    rep = {r["tool"]: r for r in tool_latency.report()}
    assert rep["ping"]["count"] == 1
    tool_latency.reset()


def test_run_records_latency_on_error():
    tool_latency.reset()

    def boom(args):
        raise RuntimeError("nope")

    out = asyncio.run(_reg("boom", boom).run("boom", {}))
    assert out.startswith("ERROR")
    rep = {r["tool"]: r for r in tool_latency.report()}
    assert rep["boom"]["count"] == 1  # recorded even though the tool failed
    tool_latency.reset()
