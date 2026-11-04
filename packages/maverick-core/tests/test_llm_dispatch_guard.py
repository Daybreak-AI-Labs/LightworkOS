"""Private conversational calls revalidate authority and bound paid dispatch."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from maverick import llm as llm_module
from maverick.llm import LLM, LLMResponse, ProviderDispatchDenied


class _Transient(Exception):
    pass


def _response():
    return LLMResponse(text="A draft", thinking=None, tool_calls=[], stop_reason="end_turn")


def _invoke(llm, asynchronous, **kwargs):
    call = llm.complete_async if asynchronous else llm.complete
    result = call(system="Private system", messages=[{"role": "user", "content": "Private message"}],
                  **kwargs)
    return asyncio.run(result) if asynchronous else result


def _client(request, *, before=None, instrumented=True):
    from maverick.retry import async_retry, sync_retry

    class Client:
        def complete(self, **_kwargs):
            if before:
                before()
            return sync_retry(request) if instrumented else request()

        async def complete_async(self, **_kwargs):
            if before:
                before()

            async def send():
                return request()

            return await async_retry(send) if instrumented else await send()

    return Client()


@pytest.fixture
def dispatcher(monkeypatch):
    from maverick import enterprise, failover_policy, privacy_egress, provider_cost_cap, retry

    state = SimpleNamespace(reserved=[], finished=[], rejected=[], clients=[])
    monkeypatch.setattr(enterprise, "assert_provider_allowed", lambda _provider: None)
    monkeypatch.setattr(privacy_egress, "maybe_redact_egress", lambda _provider, system, messages: (system, messages))
    monkeypatch.setattr(llm_module, "require_model_allowed", lambda model: model)
    for name in ("_enforce_circuit", "_enforce_provider_cap", "_feed_circuit", "_record_provider_call",
                 "_record_provider_spend", "_run_preflight", "_note_bandit"):
        monkeypatch.setattr(llm_module, name, lambda *args, **kwargs: None)
    monkeypatch.setattr(llm_module, "_estimate_call_cost", lambda *args, **kwargs: 0.0)
    monkeypatch.setattr(llm_module, "_call_spend", lambda *args, **kwargs: 0.0)
    monkeypatch.setattr(llm_module, "_hedge_ms_for", lambda _callback: None)
    monkeypatch.setattr(llm_module, "_fallback_chain_for_dispatch", lambda *args: [])
    monkeypatch.setattr(failover_policy, "order_chain", lambda chain: chain)
    monkeypatch.setattr(retry, "_retryable_exception_classes", lambda: (_Transient,))
    monkeypatch.setattr(retry, "_compute_delay", lambda *args: 0.0)
    monkeypatch.setattr(retry, "MAX_ATTEMPTS", 3)
    monkeypatch.setattr(provider_cost_cap, "current_provider_operation", lambda: None)

    def reserve(provider, projected, **kwargs):
        hold = object()
        state.reserved.append((hold, provider, projected, kwargs))
        return hold

    def finish(hold, *_args, **kwargs):
        state.finished.append((hold, kwargs.get("error")))
        return True

    def settle(hold, actual, **kwargs):
        state.rejected.append((hold, actual, kwargs))

    monkeypatch.setattr(provider_cost_cap, "reserve", reserve)
    monkeypatch.setattr(provider_cost_cap, "settle", settle)
    monkeypatch.setattr(llm_module, "_finish_provider_call", finish)
    llm = LLM(model="openai:gpt-5.5")

    def get_client(provider):
        state.clients.append(provider)
        return state.client

    monkeypatch.setattr(llm, "_get_client", get_client)
    return llm, state


@pytest.mark.parametrize("asynchronous", [False, True])
def test_conversation_records_reach_provider_without_losing_signed_blocks(dispatcher, asynchronous):
    from maverick.providers.conversation import ConversationMessage

    llm, state = dispatcher
    seen = []

    class Client:
        def complete(self, **kwargs):
            seen.append(kwargs["messages"])
            return _response()

        async def complete_async(self, **kwargs):
            seen.append(kwargs["messages"])
            return _response()

    state.client = Client()
    original = {"role": "assistant", "content": [
        {"type": "thinking", "thinking": "first", "signature": "signed-one"},
        {"type": "text", "text": "answer"},
        {"type": "thinking", "thinking": "second", "signature": "signed-two"},
    ]}
    call = llm.complete_async if asynchronous else llm.complete
    result = call(system="Private system", messages=[ConversationMessage.from_anthropic(original)])
    if asynchronous:
        result = asyncio.run(result)
    assert result.text == "A draft"
    assert seen == [[original]]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_guard_denies_before_client_setup_without_private_error(dispatcher, asynchronous):
    llm, state = dispatcher

    def denied():
        raise RuntimeError("Private source and employee identity")

    with pytest.raises(ProviderDispatchDenied) as error:
        _invoke(llm, asynchronous, dispatch_guard=denied)
    assert "Private" not in str(error.value)
    assert state.clients == state.reserved == []


@pytest.mark.parametrize("asynchronous", [False, True])
def test_revocation_during_request_preparation_prevents_first_send(dispatcher, asynchronous):
    llm, state = dispatcher
    allowed, sends = [True], []

    def guard():
        if not allowed[0]:
            raise PermissionError("revoked")

    state.client = _client(lambda: sends.append(True), before=lambda: allowed.__setitem__(0, False))
    with pytest.raises(ProviderDispatchDenied):
        _invoke(llm, asynchronous, dispatch_guard=guard)
    assert sends == []
    assert len(state.reserved) == 1
    assert state.finished == []
    assert state.rejected == [(state.reserved[0][0], 0.0, {"attempt_state": "failed"})]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_revocation_between_retries_prevents_another_send(dispatcher, asynchronous):
    llm, state = dispatcher
    allowed, sends = [True], []

    def guard():
        if not allowed[0]:
            raise PermissionError("revoked")

    def send():
        sends.append(True)
        allowed[0] = False
        raise _Transient("synthetic failure")

    state.client = _client(send)
    with pytest.raises(ProviderDispatchDenied):
        _invoke(llm, asynchronous, dispatch_guard=guard)
    assert len(sends) == len(state.reserved) == len(state.finished) == 1
    assert isinstance(state.finished[0][1], _Transient)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_one_attempt_refuses_replay_after_unknown_provider_failure(dispatcher, asynchronous):
    llm, state = dispatcher
    sends = []

    def send():
        sends.append(True)
        raise _Transient("synthetic failure")

    state.client = _client(send)
    with pytest.raises(ProviderDispatchDenied, match="attempt limit"):
        _invoke(llm, asynchronous, dispatch_guard=lambda: None, max_physical_attempts=1)
    assert len(sends) == len(state.reserved) == len(state.finished) == 1


@pytest.mark.parametrize("asynchronous", [False, True])
def test_guard_denial_does_not_select_a_fallback(dispatcher, monkeypatch, asynchronous):
    llm, state = dispatcher
    allowed = [True]
    monkeypatch.setattr(llm_module, "_fallback_chain_for_dispatch", lambda *args: ["anthropic:claude-sonnet-4-6"])

    def guard():
        if not allowed[0]:
            raise PermissionError("revoked")

    state.client = _client(_response, before=lambda: allowed.__setitem__(0, False))
    with pytest.raises(ProviderDispatchDenied):
        _invoke(llm, asynchronous, dispatch_guard=guard)
    assert state.clients == ["openai"]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_attempt_limit_carries_across_model_failover(dispatcher, monkeypatch, asynchronous):
    llm, state = dispatcher
    sends = []
    monkeypatch.setattr(llm_module, "_fallback_chain_for_dispatch", lambda *args: ["anthropic:claude-sonnet-4-6"])
    monkeypatch.setattr("maverick.failover_policy.policy_should_retry", lambda exc: not isinstance(exc, ProviderDispatchDenied))

    def send():
        sends.append(True)
        raise _Transient("synthetic failure")

    # A provider without a retry helper still consumes one envelope attempt.
    state.client = _client(send, instrumented=False)
    with pytest.raises(ProviderDispatchDenied, match="attempt limit"):
        _invoke(llm, asynchronous, max_physical_attempts=1)
    assert len(sends) == len(state.reserved) == len(state.finished) == 1


@pytest.mark.parametrize("asynchronous", [False, True])
def test_defaults_preserve_existing_provider_retries(dispatcher, asynchronous):
    llm, state = dispatcher
    sends = []

    def send():
        sends.append(True)
        if len(sends) == 1:
            raise _Transient("synthetic failure")
        return _response()

    state.client = _client(send)
    assert _invoke(llm, asynchronous).text == "A draft"
    assert len(sends) == len(state.reserved) == len(state.finished) == 2


def test_one_attempt_disables_hedging(dispatcher, monkeypatch):
    llm, state = dispatcher
    state.client = _client(_response)

    def unexpected_hedge(_callback):
        raise AssertionError("one-attempt call must not consult hedge settings")

    monkeypatch.setattr(llm_module, "_hedge_ms_for", unexpected_hedge)
    assert _invoke(llm, True, max_physical_attempts=1).text == "A draft"
    assert len(state.reserved) == 1


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, "1"])
def test_attempt_limit_validation_precedes_provider_setup(dispatcher, limit):
    llm, state = dispatcher
    with pytest.raises(ValueError, match="max_physical_attempts"):
        _invoke(llm, False, max_physical_attempts=limit)
    assert state.clients == state.reserved == []


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("option", ["dispatch_guard", "max_physical_attempts"])
def test_guarded_tool_request_is_refused_before_provider_setup(dispatcher, asynchronous, option):
    llm, state = dispatcher
    value = (lambda: None) if option == "dispatch_guard" else 1
    with pytest.raises(ProviderDispatchDenied, match="tool-free"):
        _invoke(llm, asynchronous, tools=[{"name": "example", "input_schema": {}}],
                **{option: value})
    assert state.clients == state.reserved == []


@pytest.mark.parametrize("asynchronous", [False, True])
def test_unguarded_tool_request_preserves_existing_dispatch(dispatcher, asynchronous):
    llm, state = dispatcher
    state.client = _client(_response)
    assert _invoke(llm, asynchronous, tools=[{"name": "example", "input_schema": {}}]).text == "A draft"
    assert len(state.reserved) == 1
