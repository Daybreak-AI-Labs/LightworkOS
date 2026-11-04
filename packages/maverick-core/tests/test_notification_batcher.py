"""Tests for smart notification batching.

Deterministic: the delivery callable and the clock are injected, so the
window/threshold policy is exercised without threads or real pushes.
"""
from __future__ import annotations

from maverick.notification_batcher import (
    BatchPolicy,
    NotificationBatcher,
    policy_from_config,
)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def _batcher(window=60.0, max_batch=10, clock=None):
    sends: list = []
    clk = clock or Clock()
    b = NotificationBatcher(
        BatchPolicy(window_seconds=window, max_batch=max_batch),
        send=lambda t, body, p, c: sends.append((t, body, p, c)) or 1,
        clock=clk,
    )
    return b, sends, clk


def test_disabled_passes_through():
    b, sends, _ = _batcher(window=0.0)  # batching off
    assert b.submit("step done") == 1
    assert len(sends) == 1  # sent immediately, not queued


def test_low_priority_is_queued_until_window(monkeypatch):
    b, sends, clk = _batcher(window=60.0)
    assert b.submit("a") == 0  # queued
    assert b.submit("b") == 0
    assert sends == []         # nothing sent yet
    clk.advance(61)
    assert b.maybe_flush() == 1
    assert len(sends) == 1
    title, body, _prio, _cat = sends[0]
    assert title == "2 notifications"
    assert "a" in body and "b" in body


def test_flush_on_max_batch():
    b, sends, _ = _batcher(window=600.0, max_batch=3)
    b.submit("1")
    b.submit("2")
    assert sends == []          # under the cap
    assert b.submit("3") == 1   # hits cap -> flush now
    assert len(sends) == 1
    assert sends[0][0] == "3 notifications"


def test_high_priority_bypasses_and_flushes_pending():
    b, sends, _ = _batcher(window=600.0)
    b.submit("low one")              # queued
    fired = b.submit("urgent!", priority="high")
    # flush of the pending batch (1) + the immediate high-priority send (1)
    assert fired == 2
    assert len(sends) == 2
    assert sends[0][1] == "low one"        # pending flushed first (order)
    assert sends[1][1] == "urgent!"
    assert sends[1][2] == "high"


def test_single_item_keeps_original_title_body():
    b, sends, _ = _batcher(window=5.0)
    b.submit("just me", title="Solo")
    b.flush()
    assert sends[0][0] == "Solo" and sends[0][1] == "just me"


def test_explicit_flush_sends_pending():
    b, sends, _ = _batcher(window=600.0)
    b.submit("x")
    b.submit("y")
    assert b.flush() == 1
    assert sends[0][0] == "2 notifications"
    # second flush is a no-op
    assert b.flush() == 0


def test_maybe_flush_before_window_is_noop():
    b, sends, clk = _batcher(window=60.0)
    b.submit("x")
    clk.advance(10)             # not past the window
    assert b.maybe_flush() == 0
    assert sends == []


def test_policy_from_config_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_NOTIFY_BATCH_WINDOW", "30")
    monkeypatch.setenv("MAVERICK_NOTIFY_BATCH_MAX", "5")
    p = policy_from_config()
    assert p.window_seconds == 30.0 and p.max_batch == 5 and p.is_active()


def test_policy_off_by_default(monkeypatch):
    for k in ("MAVERICK_NOTIFY_BATCH_WINDOW", "MAVERICK_NOTIFY_BATCH_MAX"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    assert policy_from_config().is_active() is False


# -- integration with notifications.notify() --------------------------------

def test_notify_routes_to_batcher_when_active(monkeypatch):
    import maverick.notification_batcher as nb
    import maverick.notifications as N

    calls: list = []

    class FakeBatcher:
        def submit(self, body, *, title, priority, category):
            calls.append((body, title, priority))
            return 0  # queued

    monkeypatch.setattr(nb, "shared", lambda: FakeBatcher())
    n = N.notify("hi", backends=["ntfy"], priority="default")
    assert n == 0 and calls == [("hi", "Lightwork", "default")]


def test_notify_sync_bypasses_batcher(monkeypatch):
    import maverick.notification_batcher as nb
    import maverick.notifications as N

    monkeypatch.setattr(nb, "shared", lambda: (_ for _ in ()).throw(
        AssertionError("batcher must not be consulted on a sync send")))
    # async_dispatch=False must take the direct path (no backend configured -> 0)
    assert N.notify("hi", backends=["none"], async_dispatch=False) == 0


def test_notify_high_priority_bypasses_batcher(monkeypatch):
    import maverick.notification_batcher as nb
    import maverick.notifications as N

    monkeypatch.setattr(nb, "shared", lambda: (_ for _ in ()).throw(
        AssertionError("high priority must bypass batching")))
    # high priority + no real backend -> direct path returns 0, batcher untouched
    assert N.notify("urgent", backends=["none"], priority="high") == 0
