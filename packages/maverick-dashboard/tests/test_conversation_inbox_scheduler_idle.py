"""The conversation inbox observer backs off while there is nothing to do.

It ran a full cycle every 3 s with no users: each cycle read the deployment
configuration (files, at-rest key, saved secrets) four times per workspace and
listed the inbox records. On network storage that was about 1,500 metered
file operations a minute from this one thread while idle.
"""
from __future__ import annotations

import threading

from maverick_dashboard import conversation_inbox_scheduler as observer


def _run_loop(monkeypatch, outcomes, *, wake_after=None):
    waits: list[float] = []
    remaining = list(outcomes)

    def cycle():
        return remaining.pop(0)

    class _Wake:
        def __init__(self):
            self.flag = False

        def wait(self, seconds):
            waits.append(seconds)
            if wake_after is not None and len(waits) == wake_after:
                self.flag = True
            if not remaining:
                observer._scheduler_stop.set()
            woke, self.flag = self.flag, False
            return woke

        def set(self):
            self.flag = True

        def clear(self):
            pass

    monkeypatch.setattr(observer, "cycle", cycle)
    monkeypatch.setattr(observer, "_wake", _Wake())
    observer._scheduler_stop.clear()
    try:
        observer._loop()
    finally:
        observer._scheduler_stop.clear()
    return waits


def test_an_idle_observer_backs_off_to_thirty_seconds(monkeypatch):
    assert _run_loop(monkeypatch, [False] * 6) == [3, 6, 12, 24, 30, 30]


def test_work_or_a_wake_returns_to_three_seconds(monkeypatch):
    assert _run_loop(monkeypatch, [False, False, True, False]) == [3, 6, 3, 6]
    assert _run_loop(monkeypatch, [False, False, False, False], wake_after=2) == [3, 6, 3, 6]


def test_each_cycle_shares_one_configuration_read(monkeypatch):
    from maverick import config

    seen = []

    def cycle():
        seen.append(config._KEPT_READ.get() is not None)
        observer._scheduler_stop.set()
        return False

    monkeypatch.setattr(observer, "cycle", cycle)
    monkeypatch.setattr(observer, "_wake", threading.Event())
    observer._scheduler_stop.clear()
    try:
        observer._loop()
    finally:
        observer._scheduler_stop.clear()
    assert seen == [True]
