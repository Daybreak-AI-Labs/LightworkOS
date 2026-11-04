"""Per-tool latency budget."""
from __future__ import annotations

import pytest
from maverick import latency_budget as lb


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))  # isolate config
    lb.reset()
    yield
    lb.reset()


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_TOOL_LATENCY_BUDGET_MS", raising=False)
    assert lb.budget_ms() == 0.0
    assert lb.note_elapsed("read_file", 5000) is None  # no budget -> no-op
    assert lb.breaches() == []


def test_breach_recorded_when_over(monkeypatch):
    monkeypatch.setenv("MAVERICK_TOOL_LATENCY_BUDGET_MS", "50")
    warning = lb.note_elapsed("slow_tool", 120.0)
    assert warning is not None and "exceeded" in warning
    b = lb.breaches()
    assert len(b) == 1
    assert b[0]["tool"] == "slow_tool"
    assert b[0]["over_ms"] == 70.0


def test_no_breach_when_under(monkeypatch):
    monkeypatch.setenv("MAVERICK_TOOL_LATENCY_BUDGET_MS", "50")
    assert lb.note_elapsed("fast", 10.0) is None
    assert lb.breaches() == []


def test_invalid_budget_is_off(monkeypatch):
    monkeypatch.setenv("MAVERICK_TOOL_LATENCY_BUDGET_MS", "not-a-number")
    assert lb.budget_ms() == 0.0


def test_breaches_are_bounded(monkeypatch):
    monkeypatch.setenv("MAVERICK_TOOL_LATENCY_BUDGET_MS", "1")
    for i in range(lb._MAX_BREACHES + 50):
        lb.note_elapsed(f"t{i}", 100.0)
    assert len(lb.breaches()) == lb._MAX_BREACHES
