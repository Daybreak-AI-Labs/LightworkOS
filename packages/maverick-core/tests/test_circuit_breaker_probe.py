"""HALF_OPEN admits exactly one probe.

CircuitBreaker.call() must not fast-fail only on OPEN: after the cooldown
flips OPEN->HALF_OPEN, letting every concurrent caller pass the gate would
re-storm the dead dependency.
"""
from __future__ import annotations

import asyncio
import threading

import pytest
from maverick.circuit_breaker import CircuitBreaker, CircuitOpen, CircuitState


def test_half_open_admits_single_probe_then_closes_on_success():
    br = CircuitBreaker("probe-test", failure_threshold=1, cooldown_seconds=0.0)

    # One failure opens it; cooldown 0 means the next tick is HALF_OPEN.
    with pytest.raises(RuntimeError):
        br.call(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert br.state is CircuitState.HALF_OPEN

    started = threading.Event()
    release = threading.Event()

    def slow_probe():
        started.set()
        release.wait(timeout=3)
        return "ok"

    probe_result: list = []
    t = threading.Thread(target=lambda: probe_result.append(br.call(slow_probe)))
    t.start()
    assert started.wait(timeout=3), "probe never started"

    # While the single probe is in flight, concurrent callers must fast-fail.
    with pytest.raises(CircuitOpen):
        br.call(lambda: "second-caller")

    release.set()
    t.join(timeout=3)
    assert probe_result == ["ok"]
    # Probe succeeded -> circuit closes and a new call is admitted.
    assert br.state is CircuitState.CLOSED
    assert br.call(lambda: "after-close") == "after-close"


def test_half_open_probe_failure_reopens_and_clears_flag():
    br = CircuitBreaker("probe-fail", failure_threshold=1, cooldown_seconds=0.0)
    with pytest.raises(RuntimeError):
        br.call(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert br.state is CircuitState.HALF_OPEN
    # The probe fails -> reopen; the in-flight flag must clear so a later
    # HALF_OPEN probe can run (not be wedged shut forever).
    with pytest.raises(RuntimeError):
        br.call(lambda: (_ for _ in ()).throw(RuntimeError("probe boom")))
    # cooldown 0 -> HALF_OPEN again, and a fresh probe is admitted.
    assert br.state is CircuitState.HALF_OPEN
    assert br.call(lambda: "recovered") == "recovered"
    assert br.state is CircuitState.CLOSED


def test_half_open_probe_cancel_reopens_and_clears_flag():
    br = CircuitBreaker("probe-cancel", failure_threshold=1, cooldown_seconds=0.0)
    with pytest.raises(RuntimeError):
        br.call(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert br.state is CircuitState.HALF_OPEN

    # asyncio.CancelledError inherits directly from BaseException on supported
    # Python versions, so it must still clear the single-probe guard.
    with pytest.raises(asyncio.CancelledError):
        br.call(lambda: (_ for _ in ()).throw(asyncio.CancelledError()))

    # cooldown 0 -> HALF_OPEN again; if the probe guard were still wedged, this
    # call would raise CircuitOpen instead of being admitted as the next probe.
    assert br.state is CircuitState.HALF_OPEN
    assert br.call(lambda: "recovered") == "recovered"
    assert br.state is CircuitState.CLOSED
