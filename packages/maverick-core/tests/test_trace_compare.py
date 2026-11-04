"""Tests for the trace_compare tool (comparative trajectory replay).
latency_heatmap + tool_call_inspector have their own suites. Deterministic."""
from __future__ import annotations

from maverick.tools.trace_compare import trace_compare

# ---- trace_compare ----

def test_trace_identical_shape():
    t = trace_compare()
    a = [{"seq": 1, "t": 1.0, "kind": "tool", "name": "fs"}, {"seq": 2, "t": 2.0, "kind": "llm"}]
    b = [{"seq": 1, "t": 9.9, "kind": "tool", "name": "fs"}, {"seq": 2, "t": 8.8, "kind": "llm"}]
    out = t.fn({"a": a, "b": b})
    assert "matched: 2/2" in out and "identical shape" in out


def test_trace_field_divergence():
    t = trace_compare()
    a = [{"seq": 1, "kind": "tool", "name": "fs"}]
    b = [{"seq": 1, "kind": "tool", "name": "shell"}]
    out = t.fn({"a": a, "b": b})
    assert "diverge-at: 0" in out and "name: 'fs' != 'shell'" in out


def test_trace_kind_divergence_and_length():
    t = trace_compare()
    a = [{"kind": "tool"}, {"kind": "llm"}]
    b = [{"kind": "tool"}]
    out = t.fn({"a": a, "b": b})
    assert "diverge-at: 1" in out and "only in a" in out


def test_trace_validation():
    t = trace_compare()
    assert t.fn({"a": "x", "b": []}).startswith("ERROR")


def test_trace_compare_registers():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "trace_compare" in names
