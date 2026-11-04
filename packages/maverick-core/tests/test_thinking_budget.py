"""Adaptive thinking-budget controller."""
from __future__ import annotations

from maverick import thinking_budget as tb


def test_none_base_stays_none():
    assert tb.adjust("writer", None, enabled=True) is None


def test_disabled_returns_base_unchanged():
    tb.reset("orchestrator")
    for _ in range(10):
        tb.record("orchestrator", True)
    assert tb.adjust("orchestrator", 8000, enabled=False) == 8000
    tb.reset("orchestrator")


def test_insufficient_data_returns_base():
    tb.reset("orchestrator")
    tb.record("orchestrator", True)  # only 1 sample (< _MIN_SAMPLES)
    assert tb.adjust("orchestrator", 8000, enabled=True) == 8000
    tb.reset("orchestrator")


def test_high_success_trims_budget():
    tb.reset("orchestrator")
    for _ in range(5):
        tb.record("orchestrator", True)   # rate 1.0 >= 0.8
    assert tb.adjust("orchestrator", 8000, enabled=True) == 6000  # 8000*0.75
    tb.reset("orchestrator")


def test_low_success_raises_budget_clamped():
    tb.reset("orchestrator")
    for _ in range(5):
        tb.record("orchestrator", False)  # rate 0.0 <= 0.4
    # 8000*1.5 = 12000, within the [2000, 16000] band
    assert tb.adjust("orchestrator", 8000, enabled=True) == 12000
    # and the raise is clamped to max_budget
    assert tb.adjust("orchestrator", 16000, enabled=True) == 16000
    tb.reset("orchestrator")


def test_mid_success_keeps_base():
    tb.reset("orchestrator")
    tb.record("orchestrator", True)
    tb.record("orchestrator", True)
    tb.record("orchestrator", False)  # rate ~0.67, between LOW and HIGH
    assert tb.adjust("orchestrator", 8000, enabled=True) == 8000
    tb.reset("orchestrator")


def test_agent_thinking_budget_default_off_unchanged(monkeypatch):
    # With the controller off (default), agent._thinking_budget returns the base
    # picks (8000 for orchestrator/revisor, None otherwise) — no behavior change.
    monkeypatch.setattr(tb, "_enabled", lambda: False)
    from maverick.agent import Agent
    a = Agent.__new__(Agent)
    a.role = "orchestrator"
    assert a._thinking_budget() == 8000
    a.role = "writer"
    assert a._thinking_budget() is None
