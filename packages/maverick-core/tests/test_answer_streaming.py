"""A chat turn shows its answer while the model writes it, and a plain chat
answer does not wait on the self-verifier.

The root agent of a conversational run (``SwarmContext.conversation_id`` set)
passes ``on_delta`` to the model and mirrors the text into the goal's result
column (``agent._PartialAnswerStream``), which the dashboard streams to the
page. A conversational answer reached with no tools, no code, and no edit
block skips the verifier round trip unless ``[verification]
verify_chat_answers`` turns it back on. Standalone goals are unchanged.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick.agent import (
    Agent,
    _answer_streaming_enabled,
    _PartialAnswerStream,
    _strip_final_marker,
    _verify_chat_answers_enabled,
)
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.llm import LLMResponse
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel

_ANSWER = (
    "FINAL: The answer is 42. " + "It follows from the question as asked, and "
    "nothing in it needs a tool, a file, or a command to settle. " * 6
).strip()
_ACCEPT = LLMResponse(
    text='{"confidence":0.8,"accepts":true,"critique":"fine","issues":[]}',
    thinking=None, tool_calls=[], stop_reason="end_turn",
)


class _StreamingLLM:
    """Scripted model that streams a response's text through ``on_delta``
    when the caller asks for it, and records what the goal showed meanwhile."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[dict] = []
        self.previews: list[str] = []
        self.world = None
        self.goal_id = None
        self.model = "fake:test"

    async def complete_async(self, **kwargs):
        self.calls.append(kwargs)
        resp = self.responses.pop(0) if self.responses else LLMResponse(
            text="FINAL: done", thinking=None, tool_calls=[], stop_reason="end_turn")
        on_delta = kwargs.get("on_delta")
        if on_delta is not None:
            for i in range(0, len(resp.text), 7):
                on_delta(resp.text[i:i + 7])
                self.previews.append(self.world.get_goal(self.goal_id).result or "")
        return resp


def _ctx(tmp_path: Path, llm, *, conversation_id) -> SwarmContext:
    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("what is the answer", "")
    llm.world, llm.goal_id = world, goal_id
    return SwarmContext(
        llm=llm, world=world, budget=Budget(max_dollars=1.0), blackboard=Blackboard(),
        sandbox=LocalBackend(workdir=tmp_path), goal_id=goal_id, max_depth=2,
        use_skills=False, conversation_id=conversation_id,
    )


@pytest.fixture(autouse=True)
def _plain_config(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    for name in ("MAVERICK_STREAM_ANSWERS", "MAVERICK_VERIFY_CHAT_ANSWERS",
                 "MAVERICK_RISK_PROPORTIONAL_VERIFY", "MAVERICK_EVIDENCE_GATEWAY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(_PartialAnswerStream, "MIN_INTERVAL", 0.0)


# --- end to end -------------------------------------------------------------

@pytest.mark.asyncio
async def test_root_chat_turn_streams_its_answer_and_skips_the_verifier(tmp_path):
    llm = _StreamingLLM([LLMResponse(text=_ANSWER, thinking=None, tool_calls=[], stop_reason="end_turn")])
    ctx = _ctx(tmp_path, llm, conversation_id=7)
    result = await Agent(ctx=ctx, role="orchestrator", brief="what is the answer").run()
    expected = _ANSWER[len("FINAL: "):]
    assert "on_delta" in llm.calls[0]
    shown = [p for p in llm.previews if p]
    assert shown, "the page saw nothing while the model was writing"
    assert all(expected.startswith(p) for p in shown)          # a growing prefix
    assert len(shown[-1]) < len(expected)                      # the tail was held back
    assert ctx.world.get_goal(ctx.goal_id).result == expected  # flushed whole at the end
    assert len(llm.calls) == 1                                 # no verifier round trip
    assert result.final == expected
    assert "conversational" in result.verifier_critique


@pytest.mark.asyncio
async def test_a_secret_split_across_deltas_never_reaches_the_preview(tmp_path):
    key = "sk-ant-api03-" + "A" * 40
    text = "FINAL: Use this key: " + key + ". " + "Then carry on with the rest of the setup. " * 5
    llm = _StreamingLLM([LLMResponse(text=text, thinking=None, tool_calls=[], stop_reason="end_turn")])
    ctx = _ctx(tmp_path, llm, conversation_id=7)
    await Agent(ctx=ctx, role="orchestrator", brief="setup").run()
    assert all(key not in p for p in llm.previews)
    assert key not in (ctx.world.get_goal(ctx.goal_id).result or "")
    assert "carry on" in (ctx.world.get_goal(ctx.goal_id).result or "")


@pytest.mark.asyncio
async def test_a_standalone_goal_neither_streams_nor_skips_verification(tmp_path):
    llm = _StreamingLLM([LLMResponse(text=_ANSWER, thinking=None, tool_calls=[], stop_reason="end_turn"), _ACCEPT])
    ctx = _ctx(tmp_path, llm, conversation_id=None)
    result = await Agent(ctx=ctx, role="orchestrator", brief="what is the answer").run()
    assert "on_delta" not in llm.calls[0]
    assert llm.previews == []
    assert len(llm.calls) == 2                                 # verifier ran
    assert result.verifier_confidence == pytest.approx(0.8)


@pytest.mark.asyncio
async def test_verify_chat_answers_restores_the_verifier(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_VERIFY_CHAT_ANSWERS", "1")
    llm = _StreamingLLM([LLMResponse(text=_ANSWER, thinking=None, tool_calls=[], stop_reason="end_turn"), _ACCEPT])
    ctx = _ctx(tmp_path, llm, conversation_id=7)
    await Agent(ctx=ctx, role="orchestrator", brief="what is the answer").run()
    assert "on_delta" in llm.calls[0]                          # streaming is independent
    assert len(llm.calls) == 2


@pytest.mark.asyncio
async def test_a_chat_answer_that_used_tools_is_still_verified(tmp_path):
    llm = _StreamingLLM([LLMResponse(text=_ANSWER, thinking=None, tool_calls=[], stop_reason="end_turn"), _ACCEPT])
    ctx = _ctx(tmp_path, llm, conversation_id=7)
    ctx.budget.tool_calls = 1                                  # as if a tool ran earlier in the turn
    await Agent(ctx=ctx, role="orchestrator", brief="what is the answer").run()
    assert len(llm.calls) == 2


@pytest.mark.asyncio
async def test_a_chat_answer_with_code_is_still_verified(tmp_path):
    coded = "FINAL: Run this:\n```sh\nrm -rf build\n```"
    llm = _StreamingLLM([LLMResponse(text=coded, thinking=None, tool_calls=[], stop_reason="end_turn"), _ACCEPT])
    ctx = _ctx(tmp_path, llm, conversation_id=7)
    await Agent(ctx=ctx, role="orchestrator", brief="clean the build").run()
    assert len(llm.calls) == 2


@pytest.mark.asyncio
async def test_streaming_can_be_switched_off(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_STREAM_ANSWERS", "0")
    llm = _StreamingLLM([LLMResponse(text=_ANSWER, thinking=None, tool_calls=[], stop_reason="end_turn")])
    ctx = _ctx(tmp_path, llm, conversation_id=7)
    await Agent(ctx=ctx, role="orchestrator", brief="what is the answer").run()
    assert "on_delta" not in llm.calls[0]


@pytest.mark.asyncio
async def test_evidence_gateway_withholds_the_preview(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_EVIDENCE_GATEWAY", "1")
    llm = _StreamingLLM([LLMResponse(text=_ANSWER, thinking=None, tool_calls=[], stop_reason="end_turn")])
    ctx = _ctx(tmp_path, llm, conversation_id=7)
    await Agent(ctx=ctx, role="orchestrator", brief="what is the answer").run()
    assert "on_delta" not in llm.calls[0]


@pytest.mark.asyncio
async def test_a_model_client_without_on_delta_gets_the_buffered_call(tmp_path):
    class _Plain:
        def __init__(self):
            self.calls = []
            self.model = "fake:test"
            self.world = self.goal_id = None
        async def complete_async(self, system, messages, tools=None, budget=None,
                                 max_tokens=4096, thinking_budget=None, model=None):
            self.calls.append(model)
            return LLMResponse(text=_ANSWER, thinking=None, tool_calls=[], stop_reason="end_turn")
    llm = _Plain()
    ctx = _ctx(tmp_path, llm, conversation_id=7)
    result = await Agent(ctx=ctx, role="orchestrator", brief="what is the answer").run()
    assert result.final == _ANSWER[len("FINAL: "):]
    assert len(llm.calls) == 1


# --- the preview writer -----------------------------------------------------

class _Recorder:
    def __init__(self, fail=False):
        self.writes: list[str] = []
        self.fail = fail
    def set_goal_partial_result(self, goal_id, text):
        if self.fail:
            raise RuntimeError("disk full")
        self.writes.append(text)
        return True


def test_preview_holds_back_a_tail_and_partial_tokens_until_finish():
    world = _Recorder()
    stream = _PartialAnswerStream(world, 1)
    stream("word " * 30)                                       # 150 chars
    shown = world.writes[-1]
    assert shown == ("word " * 10).rstrip()                    # whole words, 96 held back
    stream.finish()
    assert world.writes[-1] == ("word " * 30).rstrip() + " "


def test_an_unbroken_token_is_never_shown_half_written():
    world = _Recorder()
    stream = _PartialAnswerStream(world, 1)
    stream("A" * 300)
    assert world.writes == []                                  # still one token
    stream.finish()
    assert world.writes[-1] == "A" * 300


def test_a_secret_is_never_shown_before_it_can_be_redacted():
    """Regression: truncating before redacting leaked secret prefixes that
    the redactor cannot recognise (AKIA... one char short, a DSN before '@')."""
    world = _Recorder()
    stream = _PartialAnswerStream(world, 1)
    text = ("Use this key AKIAIOSFODNN7EXAMPLE and the DSN "  # pragma: allowlist secret
            "postgres://admin:hunter2secretpw@db.internal/prod for the job. ")  # pragma: allowlist secret
    for i in range(len(text)):
        stream(text[i])
        stream._last_flush = float("-inf")                     # flush every delta
    stream(" filler" * 30)
    stream._last_flush = float("-inf")
    stream.finish()
    for shown in world.writes:
        assert "AKIAIOSFODNN7" not in shown and "hunter2" not in shown


def test_a_shield_block_withdraws_the_preview():
    class _Shield:
        def __init__(self):
            self.calls = 0
        def scan_output(self, text):
            self.calls += 1
            return SimpleNamespace(allowed="forbidden" not in text)

    world = _Recorder()
    stream = _PartialAnswerStream(world, 1, _Shield())
    stream("safe words " * 20)
    assert world.writes and "safe" in world.writes[-1]
    stream._last_flush = float("-inf")
    stream(" forbidden content " + "x " * 60)
    stream.finish()
    assert world.writes[-1] == "" and stream._failed is True


def test_preview_is_throttled(monkeypatch):
    monkeypatch.setattr(_PartialAnswerStream, "MIN_INTERVAL", 3600.0)
    world = _Recorder()
    stream = _PartialAnswerStream(world, 1)
    for _ in range(20):
        stream("x " * 25)
    assert len(world.writes) == 1                              # first flush only
    stream.finish()
    assert world.writes[-1] == "x " * 500


def test_preview_strips_the_final_marker_once_it_arrives():
    assert _strip_final_marker("thinking aloud") == "thinking aloud"
    assert _strip_final_marker("Target: x.\nFINAL: The answer") == "The answer"
    world = _Recorder()
    stream = _PartialAnswerStream(world, 1)
    stream("Reasoning first.\nFINAL: Hello there")
    stream.finish()
    assert world.writes[-1] == "Hello there"


def test_preview_fails_closed_on_a_write_error():
    world = _Recorder(fail=True)
    stream = _PartialAnswerStream(world, 1)
    stream("some text " * 20)
    stream.finish()                                            # no exception
    assert stream.writes == 0 and stream._failed is True


def test_preview_is_capped_and_never_ends_on_a_cut_token():
    world = _Recorder()
    stream = _PartialAnswerStream(world, 1)
    stream("word " * (_PartialAnswerStream.MAX_CHARS // 5 + 100))
    stream.finish()
    shown = world.writes[-1]
    assert len(shown) <= _PartialAnswerStream.MAX_CHARS and shown.endswith("word")


def test_a_stream_cut_at_the_token_limit_never_shows_a_partial_secret():
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # pragma: allowlist secret
    world = _Recorder()
    stream = _PartialAnswerStream(world, 1)
    stream("Here is the token you asked me to rotate: " + token[:30])
    stream.finish(complete=False)                              # stop_reason max_tokens
    assert all(token[:20] not in w for w in world.writes)


@pytest.mark.parametrize("stop, shown_whole", [
    ("end_turn", True), ("max_tokens", False), ("model_context_window_exceeded", False),
    ("refusal", False), (None, False)])
@pytest.mark.asyncio
async def test_the_last_flush_follows_the_stop_reason(tmp_path, stop, shown_whole):
    text = "FINAL: " + "all good here " * 12 + "tail-token"
    llm = _StreamingLLM([LLMResponse(text=text, thinking=None, tool_calls=[], stop_reason=stop)])
    ctx = _ctx(tmp_path, llm, conversation_id=7)
    agent = Agent(ctx=ctx, role="orchestrator", brief="b")
    seen: list = []
    real = ctx.world.set_goal_partial_result
    ctx.world.set_goal_partial_result = lambda gid, t: seen.append(t) or real(gid, t)
    await agent.run()
    assert any("tail-token" in w for w in seen) is shown_whole


def test_an_open_quoted_secret_is_held_until_its_quote_closes():
    words = " ".join(f"word{i:02d}" for i in range(30))
    world = _Recorder()
    stream = _PartialAnswerStream(world, 1)
    stream("Set this up first. " * 8 + "\nAPI_TOKEN=\"" + words + " " + "more " * 40)
    assert world.writes and all("word05" not in w for w in world.writes)
    stream._last_flush = float("-inf")
    stream('"\nThen restart the service. ' + "ok " * 40)
    stream.finish()
    assert all("word05" not in w for w in world.writes)
    assert "restart the service" in world.writes[-1]


def test_the_chat_page_clears_a_withdrawn_preview():
    page = (Path(__file__).resolve().parents[2] / "maverick-dashboard" / "maverick_dashboard"
            / "templates" / "chat_goal.html").read_text(encoding="utf-8")
    assert "} else if (d.result === '' && lastResult) {" in page


# --- switches ---------------------------------------------------------------

def test_streaming_defaults_on_and_follows_config(monkeypatch):
    assert _answer_streaming_enabled() is True
    monkeypatch.setattr("maverick.config.load_config", lambda: {"chat": {"stream_answers": False}})
    assert _answer_streaming_enabled() is False
    monkeypatch.setenv("MAVERICK_STREAM_ANSWERS", "1")
    assert _answer_streaming_enabled() is True


def test_chat_verification_defaults_off_and_follows_config(monkeypatch):
    assert _verify_chat_answers_enabled() is False
    monkeypatch.setattr("maverick.config.load_config", lambda: {"verification": {"verify_chat_answers": True}})
    assert _verify_chat_answers_enabled() is True
    monkeypatch.setenv("MAVERICK_VERIFY_CHAT_ANSWERS", "0")
    assert _verify_chat_answers_enabled() is False


# --- provider ---------------------------------------------------------------

class _FakeStream:
    def __init__(self, chunks, final):
        self._chunks, self._final = chunks, final
    async def __aenter__(self):
        return self
    async def __aexit__(self, *exc):
        return False
    @property
    def text_stream(self):
        async def gen():
            for c in self._chunks:
                yield c
        return gen()
    async def get_final_message(self):
        return self._final


@pytest.mark.asyncio
async def test_anthropic_complete_async_streams_when_asked(monkeypatch):
    from maverick.providers.anthropic_provider import AnthropicClient

    provider = AnthropicClient(api_key="sk-ant-test-not-real")  # pragma: allowlist secret
    final = SimpleNamespace(
        content=[SimpleNamespace(type="text", text="hello world")],
        usage=SimpleNamespace(input_tokens=3, output_tokens=2,
                              cache_creation_input_tokens=0, cache_read_input_tokens=0),
        stop_reason="end_turn", model="claude-sonnet-4-6",
    )
    seen: list[dict] = []

    def stream(**kwargs):
        seen.append(kwargs)
        return _FakeStream(["hello ", "world"], final)

    async def create(**kwargs):
        raise AssertionError("buffered create must not be used when streaming")

    provider.aclient = SimpleNamespace(
        messages=SimpleNamespace(stream=stream, create=create),
        beta=SimpleNamespace(messages=SimpleNamespace(stream=stream, create=create)),
    )
    deltas: list[str] = []
    resp = await provider.complete_async(
        system="s", messages=[{"role": "user", "content": "hi"}], on_delta=deltas.append,
        model="claude-sonnet-4-6",
    )
    assert deltas == ["hello ", "world"]
    assert resp.text == "hello world"
    assert seen and seen[0]["model"]


@pytest.mark.asyncio
async def test_llm_forwards_on_delta_only_to_anthropic(monkeypatch):
    from maverick.llm import LLM

    class _Client:
        CACHE_READ_MULT = None
        def __init__(self):
            self.kwargs = None
        async def complete_async(self, **kwargs):
            self.kwargs = kwargs
            return LLMResponse(text="ok", thinking=None, tool_calls=[], stop_reason="end_turn")

    clients: dict[str, _Client] = {}
    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: clients.setdefault(provider, _Client()))
    llm = LLM()
    cb = lambda _t: None  # noqa: E731
    await llm.complete_async("s", [{"role": "user", "content": "hi"}], model="anthropic:claude-sonnet-4-6", on_delta=cb)
    assert clients["anthropic"].kwargs.get("on_delta") is cb
    await llm.complete_async("s", [{"role": "user", "content": "hi"}], model="openai:gpt-5.5", on_delta=cb)
    assert "on_delta" not in clients["openai"].kwargs


def test_failover_attempt_starts_a_fresh_preview():
    """Regression: failover reused one callback, so a failed attempt's partial
    text was concatenated with the next model's answer."""
    from maverick.llm import _attempt_delta
    world = _Recorder()
    stream = _PartialAnswerStream(world, 1)
    _attempt_delta(stream)("the first model began " * 3)
    _attempt_delta(stream)("second model answer ")          # failover: new attempt
    stream.finish()
    assert world.writes[-1] == "second model answer "
    assert _attempt_delta(None) is None and _attempt_delta(print) is print


def test_text_without_spaces_previews_at_character_boundaries():
    world = _Recorder()
    stream = _PartialAnswerStream(world, 1)
    answer = "这是一个很长的回答，" * 30                        # no spaces at all
    stream(answer + "密钥是 sk-ant-api03-" + "B" * 20)             # key still being written
    assert world.writes and answer.startswith(world.writes[-1].rstrip())
    assert "sk-ant" not in world.writes[-1]
