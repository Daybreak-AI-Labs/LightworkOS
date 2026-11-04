"""Tests for PRM-in-loop guidance: the reward model steers the agent loop."""
from __future__ import annotations

from maverick.prm_guidance import PromiseWindow, maybe_nudge, should_nudge


def test_should_nudge_on_low_streak():
    assert should_nudge([0.8, 0.2, 0.1, 0.15], low=0.35, streak=3)


def test_no_nudge_when_a_recent_step_is_promising():
    assert not should_nudge([0.1, 0.1, 0.9], low=0.35, streak=3)


def test_no_nudge_before_enough_steps():
    assert not should_nudge([0.1, 0.1], low=0.35, streak=3)


def test_maybe_nudge_off_when_explicitly_disabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_PRM_GUIDANCE", "0")
    assert maybe_nudge([0.1, 0.1, 0.1]) is None


def test_maybe_nudge_on_when_enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_PRM_GUIDANCE", "1")
    note = maybe_nudge([0.1, 0.1, 0.1])
    assert note and "process-reward" in note


def test_promise_window_bounds_and_order():
    w = PromiseWindow(maxlen=3)
    for p in [0.1, 0.2, 0.3, 0.4]:
        w.push(p)
    assert w.values() == [0.2, 0.3, 0.4]
    w.push(None)  # ignored
    assert len(w.values()) == 3
