"""tool_call_inspector: per-tool aggregation of a tool-call log."""
from __future__ import annotations

from maverick.tools.tool_call_inspector import tool_call_inspector


def _run(calls, op="summarize"):
    return tool_call_inspector().fn({"op": op, "calls": calls})


def test_per_tool_counts_and_success_rate():
    out = _run([
        {"tool": "read", "ok": True, "ms": 10},
        {"tool": "read", "ok": False, "ms": 30},
        {"tool": "write", "ok": True, "ms": 20},
    ])
    assert "3 call(s), 2 tool(s)" in out
    assert "2x read: 1/2 ok (50%)" in out
    assert "1x write: 1/1 ok (100%)" in out


def test_total_and_mean_latency():
    out = _run([
        {"tool": "x", "ok": True, "ms": 100},
        {"tool": "x", "ok": True, "ms": 300},
    ])
    assert "total=400ms" in out
    assert "mean=200.0ms" in out


def test_total_cost_summed():
    out = _run([
        {"tool": "a", "ok": True, "ms": 1, "cost": 0.5},
        {"tool": "b", "ok": True, "ms": 1, "cost": 1.25},
    ])
    assert "cost=1.75" in out


def test_slowest_and_most_failed():
    out = _run([
        {"tool": "fast", "ok": True, "ms": 5},
        {"tool": "slow", "ok": True, "ms": 500},
        {"tool": "flaky", "ok": False, "ms": 10},
        {"tool": "flaky", "ok": False, "ms": 10},
    ])
    assert "slowest=slow" in out
    assert "most-failed=flaky (2 fail)" in out


def test_missing_cost_defaults_zero():
    out = _run([{"tool": "a", "ok": True, "ms": 5}])
    assert "cost=0" in out


def test_errors():
    t = tool_call_inspector()
    assert t.fn({"op": "summarize", "calls": []}).startswith("ERROR")
    assert t.fn({"op": "summarize"}).startswith("ERROR")
    assert t.fn({"op": "nope", "calls": [{"tool": "a", "ok": True, "ms": 1}]}).startswith("ERROR")
