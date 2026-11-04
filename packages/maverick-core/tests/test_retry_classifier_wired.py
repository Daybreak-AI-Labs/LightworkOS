"""retry_classifier is wired into retry.py: terminal error classes (auth,
content-filter, context-overflow) must stop retrying immediately even when
the exception type/status looks transient."""
import maverick.retry as retry
import pytest


class _FakeStatusError(Exception):
    """Mimics anthropic.APIStatusError: a status_code + a message."""
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def test_terminal_classifier_stops_status_less_retryable(monkeypatch):
    """A retryable *type* with no status_code (e.g. APIConnectionError) but a
    terminal message ('invalid api key') is the case the classifier uniquely
    catches: _is_retryable_status_error returns True (status is None), so
    without _is_terminal it would burn all 5 attempts."""
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        # No status_code -> _is_retryable_status_error() is True; only the
        # classifier (message -> AUTH) can mark it terminal.
        raise _FakeStatusError("Connection error: invalid api key", status_code=None)

    monkeypatch.setattr(retry, "_retryable_exception_classes",
                        lambda: (_FakeStatusError,))
    slept = []
    monkeypatch.setattr(retry.time, "sleep", lambda d: slept.append(d))

    try:
        retry.sync_retry(fn)
    except _FakeStatusError:
        pass
    # auth is terminal -> exactly one attempt, no backoff sleep
    assert calls["n"] == 1
    assert slept == []


def test_context_overflow_message_not_retried(monkeypatch):
    """A transient-looking timeout type whose message is a context overflow
    must not retry (waiting won't shrink the prompt)."""
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        raise _FakeStatusError("maximum context length exceeded", status_code=None)

    monkeypatch.setattr(retry, "_retryable_exception_classes",
                        lambda: (_FakeStatusError,))
    monkeypatch.setattr(retry.time, "sleep", lambda d: None)
    try:
        retry.sync_retry(fn)
    except _FakeStatusError:
        pass
    assert calls["n"] == 1


def test_transient_error_still_retries(monkeypatch):
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        if calls["n"] < 3:
            raise _FakeStatusError("503 service unavailable", status_code=503)
        return "ok"

    monkeypatch.setattr(retry, "_retryable_exception_classes",
                        lambda: (_FakeStatusError,))
    monkeypatch.setattr(retry.time, "sleep", lambda d: None)

    assert retry.sync_retry(fn) == "ok"
    assert calls["n"] == 3  # retried twice, succeeded on the third


def test_is_terminal_classification():
    assert retry._is_terminal(_FakeStatusError("401 unauthorized")) is True
    assert retry._is_terminal(_FakeStatusError("content blocked by safety filter")) is True
    assert retry._is_terminal(_FakeStatusError("maximum context length exceeded")) is True
    assert retry._is_terminal(_FakeStatusError("503 service unavailable")) is False
    assert retry._is_terminal(_FakeStatusError("connection reset")) is False


def test_wrapped_egress_block_is_not_retried_via_explicit_cause(monkeypatch):
    """An SDK APIConnectionError must not hide a fail-closed transport denial."""
    from maverick.enterprise import EgressBlocked

    calls = []
    slept = []

    def blocked():
        calls.append(1)
        try:
            raise EgressBlocked("openai")
        except EgressBlocked as exc:
            raise _FakeStatusError("connection error") from exc

    monkeypatch.setattr(
        retry, "_retryable_exception_classes", lambda: (_FakeStatusError,),
    )
    monkeypatch.setattr(retry.time, "sleep", lambda delay: slept.append(delay))

    with pytest.raises(_FakeStatusError, match="connection error"):
        retry.sync_retry(blocked)
    assert calls == [1]
    assert slept == []


@pytest.mark.asyncio
async def test_wrapped_egress_block_is_not_retried_via_implicit_context(monkeypatch):
    """The async path also preserves a buried policy denial without backoff."""
    from maverick.enterprise import EgressBlocked

    calls = []

    async def blocked():
        calls.append(1)
        try:
            raise EgressBlocked("anthropic")
        except EgressBlocked:
            raise _FakeStatusError("connection error") from None

    monkeypatch.setattr(
        retry, "_retryable_exception_classes", lambda: (_FakeStatusError,),
    )

    with pytest.raises(_FakeStatusError, match="connection error"):
        await retry.async_retry(blocked)
    assert calls == [1]
