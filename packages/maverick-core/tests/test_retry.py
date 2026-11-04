"""Retry/backoff for transient LLM provider errors."""
from __future__ import annotations

import pytest
from maverick import retry


def test_max_attempts_clamped_to_at_least_one(monkeypatch):
    """A 0/negative MAVERICK_LLM_RETRY_ATTEMPTS must not make the wrapped fn
    never run: range(0) leaves `last` None and dies on `assert last is not None`,
    so the provider call silently never dispatches. The clamp guarantees >=1."""
    import importlib

    monkeypatch.setenv("MAVERICK_LLM_RETRY_ATTEMPTS", "0")
    importlib.reload(retry)
    try:
        assert retry.MAX_ATTEMPTS == 1
        calls = []

        def ok():
            calls.append(1)
            return "done"

        assert retry.sync_retry(ok) == "done"
        assert calls == [1]
    finally:
        monkeypatch.delenv("MAVERICK_LLM_RETRY_ATTEMPTS", raising=False)
        importlib.reload(retry)


def test_sync_retry_succeeds_after_transient_errors(monkeypatch):
    """A retryable error followed by success returns the success value."""
    monkeypatch.setattr(retry, "BASE_DELAY", 0.001)
    monkeypatch.setattr(retry, "MAX_ATTEMPTS", 3)

    calls = []

    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise ConnectionError("transient")
        return "ok"

    # Pretend ConnectionError is in the retryable list.
    monkeypatch.setattr(
        retry, "_retryable_exception_classes", lambda: (ConnectionError,),
    )
    assert retry.sync_retry(flaky) == "ok"
    assert len(calls) == 3


def test_sync_retry_gives_up_after_max(monkeypatch):
    monkeypatch.setattr(retry, "BASE_DELAY", 0.001)
    monkeypatch.setattr(retry, "MAX_ATTEMPTS", 2)
    monkeypatch.setattr(
        retry, "_retryable_exception_classes", lambda: (ConnectionError,),
    )

    def always_fails():
        raise ConnectionError("nope")

    with pytest.raises(ConnectionError):
        retry.sync_retry(always_fails)


def test_sync_retry_does_not_retry_non_retryable(monkeypatch):
    monkeypatch.setattr(retry, "MAX_ATTEMPTS", 5)
    monkeypatch.setattr(
        retry, "_retryable_exception_classes", lambda: (ConnectionError,),
    )

    calls = []

    def boom():
        calls.append(1)
        raise ValueError("not transient")

    with pytest.raises(ValueError):
        retry.sync_retry(boom)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_async_retry_succeeds_after_transient(monkeypatch):
    monkeypatch.setattr(retry, "BASE_DELAY", 0.001)
    monkeypatch.setattr(retry, "MAX_ATTEMPTS", 3)
    monkeypatch.setattr(
        retry, "_retryable_exception_classes", lambda: (ConnectionError,),
    )

    calls = []

    async def flaky():
        calls.append(1)
        if len(calls) < 2:
            raise ConnectionError("transient")
        return "ok"

    assert await retry.async_retry(flaky) == "ok"
    assert len(calls) == 2


def test_compute_delay_honors_retry_after(monkeypatch):
    """If the exception carries a Retry-After header, use it instead
    of exponential backoff."""
    monkeypatch.setattr(retry, "MAX_DELAY", 30.0)

    class _Resp:
        headers = {"Retry-After": "7"}

    e = ConnectionError("rate limited")
    e.response = _Resp()  # type: ignore
    assert retry._compute_delay(0, e) == 7.0


def test_is_retryable_status_error():
    """Anthropic-style APIStatusError: only retry 429 and 5xx."""
    class E(Exception):
        def __init__(self, status):
            self.status_code = status

    assert retry._is_retryable_status_error(E(429)) is True
    assert retry._is_retryable_status_error(E(500)) is True
    assert retry._is_retryable_status_error(E(503)) is True
    assert retry._is_retryable_status_error(E(400)) is False
    assert retry._is_retryable_status_error(E(401)) is False
    assert retry._is_retryable_status_error(E(404)) is False


# ---------- Retry-After clamp ----------

def test_retry_after_negative_is_clamped(monkeypatch):
    from maverick import retry

    class _Resp:
        headers = {"Retry-After": "-1"}

    e = ConnectionError("rate limited")
    e.response = _Resp()  # type: ignore[attr-defined]
    delay = retry._compute_delay(0, e)
    assert delay >= 0.0  # not -1 → no ValueError downstream


def test_retry_after_huge_is_clamped(monkeypatch):
    """Server returning Retry-After: 99999 must not block for a day."""
    from maverick import retry
    monkeypatch.setattr(retry, "MAX_DELAY", 30.0)

    class _Resp:
        headers = {"Retry-After": "99999"}

    e = ConnectionError("rate limited")
    e.response = _Resp()  # type: ignore[attr-defined]
    delay = retry._compute_delay(0, e)
    assert delay <= 30.0
