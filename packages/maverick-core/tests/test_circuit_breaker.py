"""Tests for the circuit breaker (maverick.circuit_breaker)."""
from __future__ import annotations

import time

import pytest
from maverick.circuit_breaker import CircuitBreaker, CircuitOpen, CircuitState


def test_half_open_rejects_concurrent_probe():
    cb = CircuitBreaker("t")
    cb._state = CircuitState.HALF_OPEN
    cb._probe_in_flight = True  # a probe is already running
    with pytest.raises(CircuitOpen, match="in flight"):
        cb.call(lambda: "x")


def test_half_open_allows_one_probe_and_clears_flag():
    cb = CircuitBreaker("t")
    cb._state = CircuitState.HALF_OPEN
    assert cb.call(lambda: "ok") == "ok"
    assert cb._probe_in_flight is False  # cleared after the probe resolves


def test_half_open_clears_flag_on_failure():
    cb = CircuitBreaker("t")
    cb._state = CircuitState.HALF_OPEN
    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert cb._probe_in_flight is False


# ---------- circuit breaker: honor explicit reconfig on existing key ----

def test_circuit_breaker_reconfigures_existing_key():
    from maverick.circuit_breaker import get, reset_all
    reset_all()
    first = get("svc")  # defaults: threshold 5, cooldown 30
    assert first.failure_threshold == 5
    again = get("svc", failure_threshold=2, cooldown_seconds=120)
    assert again is first  # same instance
    assert again.failure_threshold == 2  # override applied, not ignored
    assert again.cooldown_seconds == 120
    reset_all()


def test_circuit_breaker_default_get_does_not_clobber():
    from maverick.circuit_breaker import get, reset_all
    reset_all()
    get("svc2", failure_threshold=2)
    # A later default get() must NOT reset the custom threshold back to 5.
    again = get("svc2")
    assert again.failure_threshold == 2
    reset_all()


# ---------- Circuit breaker ----------

def test_circuit_breaker_starts_closed():
    from maverick.circuit_breaker import CircuitBreaker, CircuitState
    br = CircuitBreaker("test1", failure_threshold=3, cooldown_seconds=1)
    assert br.state is CircuitState.CLOSED
    br.call(lambda: 42)
    assert br.state is CircuitState.CLOSED


def test_circuit_breaker_opens_after_failures():
    from maverick.circuit_breaker import (
        CircuitBreaker,
        CircuitOpen,
        CircuitState,
    )

    def _boom():
        raise RuntimeError("nope")

    br = CircuitBreaker("test2", failure_threshold=2, cooldown_seconds=10)
    for _ in range(2):
        try:
            br.call(_boom)
        except RuntimeError:
            pass
    assert br.state is CircuitState.OPEN
    try:
        br.call(lambda: 1)
    except CircuitOpen:
        return
    raise AssertionError("expected CircuitOpen")


def test_circuit_breaker_half_open_after_cooldown():
    from maverick.circuit_breaker import CircuitBreaker, CircuitState
    br = CircuitBreaker("test3", failure_threshold=1, cooldown_seconds=0.01)
    try:
        br.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))
    except RuntimeError:
        pass
    assert br.state is CircuitState.OPEN
    time.sleep(0.02)
    assert br.state is CircuitState.HALF_OPEN
    # A successful probe closes the breaker.
    br.call(lambda: 1)
    assert br.state is CircuitState.CLOSED


def test_circuit_breaker_half_open_failure_reopens():
    from maverick.circuit_breaker import CircuitBreaker, CircuitState
    br = CircuitBreaker("test4", failure_threshold=1, cooldown_seconds=0.01)
    try:
        br.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))
    except RuntimeError:
        pass
    time.sleep(0.02)
    assert br.state is CircuitState.HALF_OPEN
    try:
        br.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))
    except RuntimeError:
        pass
    assert br.state is CircuitState.OPEN


def test_circuit_breaker_registry_singleton():
    from maverick.circuit_breaker import get, reset_all
    reset_all()
    a = get("shared-key")
    b = get("shared-key")
    assert a is b


def test_circuit_breaker_snapshot():
    from maverick.circuit_breaker import get, reset_all, snapshot
    reset_all()
    br = get("snap-key", failure_threshold=2)
    br.record_success()
    rows = snapshot()
    assert any(r["key"] == "snap-key" for r in rows)


def test_late_success_does_not_close_an_open_breaker_inside_its_cooldown():
    br = CircuitBreaker("late-success", failure_threshold=2, cooldown_seconds=1000)
    br.record_failure()
    br.record_failure()
    br.record_success()
    assert br.state is CircuitState.OPEN
