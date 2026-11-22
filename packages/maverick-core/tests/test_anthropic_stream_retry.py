"""A streamed Anthropic call is retried like a buffered one.

Every dashboard task streams its answer. The SDK's own retries are off
(``max_retries=0``) because ``maverick.retry`` owns them, but the streaming
path did not go through that loop, so a single 500, 529, 429 or dropped
connection failed the whole task. A stream is now retried on the same
transient errors, as long as no text was shown or the preview can start over.
"""
from __future__ import annotations

from types import SimpleNamespace

import anthropic
import httpx
import pytest
from maverick import retry
from maverick.providers.anthropic_provider import AnthropicClient

_REQUEST = httpx.Request("POST", "https://api.anthropic.com/v1/messages")


def _status(code: int) -> anthropic.APIStatusError:
    response = httpx.Response(code, request=_REQUEST, headers={"retry-after": "0"})
    cls = {429: anthropic.RateLimitError, 500: anthropic.InternalServerError,
           400: anthropic.BadRequestError}.get(code, anthropic.APIStatusError)
    return cls(f"fake {code}", response=response, body=None)


def _final(text="hello world"):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        usage=SimpleNamespace(input_tokens=3, output_tokens=2,
                              cache_creation_input_tokens=0, cache_read_input_tokens=0),
        stop_reason="end_turn", model="claude-sonnet-4-6",
    )


class _Stream:
    """One scripted stream: raise ``open_error`` on entry, or yield ``chunks``
    and then raise ``mid_error`` (if any) instead of finishing."""

    def __init__(self, chunks=(), final=None, open_error=None, mid_error=None):
        self.chunks, self.final = list(chunks), final
        self.open_error, self.mid_error = open_error, mid_error

    def _gen(self):
        yield from self.chunks
        if self.mid_error is not None:
            raise self.mid_error

    async def _agen(self):
        for chunk in self.chunks:
            yield chunk
        if self.mid_error is not None:
            raise self.mid_error

    def __enter__(self):
        if self.open_error is not None:
            raise self.open_error
        return self

    def __exit__(self, *exc):
        return False

    async def __aenter__(self):
        return self.__enter__()

    async def __aexit__(self, *exc):
        return False

    @property
    def text_stream(self):
        return self._agen() if self._async else self._gen()

    def get_final_message(self):
        return self.final

    # Usage of an aborted stream: what the provider records for a cut stream.
    current_message_snapshot = None


class _AsyncStream(_Stream):
    _async = True

    async def get_final_message(self):
        return self.final


class _SyncStream(_Stream):
    _async = False


def _provider(script, *, is_async):
    provider = AnthropicClient(api_key="sk-ant-test-not-real")  # pragma: allowlist secret
    calls = []

    def stream(**kwargs):
        calls.append(kwargs)
        return script.pop(0)

    def create(**kwargs):
        raise AssertionError("a streamed call must not fall back to the buffered create")

    endpoint = SimpleNamespace(messages=SimpleNamespace(stream=stream, create=create),
                               beta=SimpleNamespace(messages=SimpleNamespace(stream=stream, create=create)))
    if is_async:
        provider.aclient = endpoint
    else:
        provider.client = endpoint
    return provider, calls


class _Preview:
    """Like the agent's answer preview: it can start over for a new attempt."""

    def __init__(self):
        self.text, self.resets = "", 0

    def __call__(self, delta):
        self.text += delta

    def reset(self):
        self.text, self.resets = "", self.resets + 1


@pytest.fixture(autouse=True)
def _no_wait(monkeypatch):
    monkeypatch.setattr(retry, "_compute_delay", lambda attempt, exc: 0.0)


async def _run(provider, on_delta, *, is_async):
    kwargs = dict(system="s", messages=[{"role": "user", "content": "hi"}], on_delta=on_delta,
                  model="claude-sonnet-4-6")
    if is_async:
        return await provider.complete_async(**kwargs)
    return provider.complete(**kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [True, False])
@pytest.mark.parametrize("error", [
    _status(500), _status(429), anthropic.APIConnectionError(request=_REQUEST),
], ids=["server-error", "rate-limited", "connection-dropped"])
async def test_a_transient_error_before_any_text_is_retried(is_async, error):
    kind = _AsyncStream if is_async else _SyncStream
    provider, calls = _provider([kind(open_error=error), kind(["hello ", "world"], _final())],
                                is_async=is_async)
    shown: list[str] = []
    resp = await _run(provider, shown.append, is_async=is_async)
    assert resp.text == "hello world"
    assert shown == ["hello ", "world"]
    assert len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [True, False])
async def test_repeated_rate_limits_use_every_configured_attempt(is_async):
    kind = _AsyncStream if is_async else _SyncStream
    script = [kind(open_error=_status(429)) for _ in range(retry.MAX_ATTEMPTS - 1)]
    provider, calls = _provider([*script, kind(["ok"], _final("ok"))], is_async=is_async)
    resp = await _run(provider, lambda _t: None, is_async=is_async)
    assert resp.text == "ok" and len(calls) == retry.MAX_ATTEMPTS


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [True, False])
async def test_a_cut_stream_starts_the_preview_over_and_retries(is_async):
    kind = _AsyncStream if is_async else _SyncStream
    provider, calls = _provider([
        kind(["the first att"], mid_error=anthropic.APIConnectionError(request=_REQUEST)),
        kind(["hello ", "world"], _final()),
    ], is_async=is_async)
    preview = _Preview()
    resp = await _run(provider, preview, is_async=is_async)
    assert resp.text == "hello world"
    assert preview.text == "hello world" and preview.resets == 1
    assert len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [True, False])
async def test_text_already_shown_without_a_reset_is_never_repeated(is_async):
    kind = _AsyncStream if is_async else _SyncStream
    provider, calls = _provider([
        kind(["the first att"], mid_error=anthropic.APIConnectionError(request=_REQUEST)),
        kind(["hello ", "world"], _final()),
    ], is_async=is_async)
    shown: list[str] = []
    with pytest.raises(anthropic.APIConnectionError):
        await _run(provider, shown.append, is_async=is_async)
    assert shown == ["the first att"] and len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [True, False])
async def test_a_request_error_is_not_retried(is_async):
    kind = _AsyncStream if is_async else _SyncStream
    provider, calls = _provider([kind(open_error=_status(400)), kind(["x"], _final("x"))],
                                is_async=is_async)
    with pytest.raises(anthropic.BadRequestError):
        await _run(provider, lambda _t: None, is_async=is_async)
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [True, False])
async def test_a_stream_that_ends_without_a_stop_reason_is_not_a_finished_answer(is_async):
    # The SDK ends iteration quietly when the connection closes mid-answer and
    # returns the text so far with no stop reason. That half answer must not
    # become the task's result: it is retried like a dropped connection.
    kind = _AsyncStream if is_async else _SyncStream
    cut = _final("half an ans")
    cut.stop_reason = None
    provider, calls = _provider([kind(["half an ans"], cut), kind(["hello ", "world"], _final())],
                                is_async=is_async)
    preview = _Preview()
    resp = await _run(provider, preview, is_async=is_async)
    assert resp.text == "hello world" and preview.text == "hello world"
    assert len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [True, False])
async def test_a_stream_cut_on_every_attempt_fails_instead_of_returning_half(is_async):
    kind = _AsyncStream if is_async else _SyncStream
    script = []
    for _ in range(retry.MAX_ATTEMPTS):
        cut = _final("half")
        cut.stop_reason = None
        script.append(kind(["half"], cut))
    provider, calls = _provider(script, is_async=is_async)
    with pytest.raises(anthropic.APIConnectionError):
        await _run(provider, _Preview(), is_async=is_async)
    assert len(calls) == retry.MAX_ATTEMPTS


class _Unreadable(_Stream):
    """The SDK asserts when the body was not an event stream (an HTML page)."""

    def get_final_message(self):
        raise AssertionError


class _AsyncUnreadable(_AsyncStream):
    async def get_final_message(self):
        raise AssertionError


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [True, False])
async def test_a_reply_that_is_not_an_event_stream_is_retried(is_async):
    kind = _AsyncStream if is_async else _SyncStream
    bad = _AsyncUnreadable() if is_async else type("_SyncUnreadable", (_Unreadable,), {"_async": False})()
    provider, calls = _provider([bad, kind(["ok"], _final("ok"))], is_async=is_async)
    resp = await _run(provider, _Preview(), is_async=is_async)
    assert resp.text == "ok" and len(calls) == 2
