"""A 200 reply whose body is not JSON (a proxy's or gateway's HTML page) is
retried like a dropped connection, not raised as a raw JSONDecodeError."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from maverick import retry
from maverick.providers.openai_provider import OpenAIClient
from openai.types.chat import ChatCompletion

_OK = ChatCompletion.model_validate({
    "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-5.5",
    "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "hello"}}],
    "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
})


@pytest.fixture(autouse=True)
def _no_wait(monkeypatch):
    monkeypatch.setattr(retry, "_compute_delay", lambda attempt, exc: 0.0)


def _client(replies, *, is_async):
    provider = OpenAIClient(api_key="sk-test-not-real")  # pragma: allowlist secret
    calls = []

    def answer():
        calls.append(1)
        reply = replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    async def acreate(**_kwargs):
        return answer()

    completions = SimpleNamespace(create=(acreate if is_async else (lambda **_kwargs: answer())))
    target = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    if is_async:
        provider._async = target
    else:
        provider._sync = target
    return provider, calls


def _unreadable():
    return json.JSONDecodeError("Expecting value", "<html>not json</html>", 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [True, False])
async def test_an_unreadable_reply_is_retried(is_async):
    provider, calls = _client([_unreadable(), _OK], is_async=is_async)
    kwargs = dict(system="s", messages=[{"role": "user", "content": "hi"}], model="gpt-5.5")
    resp = await provider.complete_async(**kwargs) if is_async else provider.complete(**kwargs)
    assert resp.text == "hello" and len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [True, False])
async def test_a_reply_that_stays_unreadable_fails_with_a_plain_error(is_async):
    import openai

    provider, calls = _client([_unreadable() for _ in range(retry.MAX_ATTEMPTS)], is_async=is_async)
    kwargs = dict(system="s", messages=[{"role": "user", "content": "hi"}], model="gpt-5.5")
    with pytest.raises(openai.APIConnectionError, match="could not be read"):
        await provider.complete_async(**kwargs) if is_async else provider.complete(**kwargs)
    assert len(calls) == retry.MAX_ATTEMPTS
