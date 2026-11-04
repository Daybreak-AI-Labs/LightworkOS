"""Native async compaction, stop propagation and paired-message preservation."""
from __future__ import annotations

import asyncio
import copy
import time
from types import SimpleNamespace

import pytest
from maverick import killswitch
from maverick.budget import Budget, BudgetExceeded, UsageAccountingError
from maverick.compaction import compact_messages
from maverick.compaction import plugins as cp
from maverick.compaction.strategies import compact_with_strategy, compact_with_strategy_async

STRATEGIES = ("learned", "multimodal", "streaming", "graph")


def _history():
    messages = [{"role": "user" if i % 2 == 0 else "assistant",
                 "content": f"service_{i} | requires | database"} for i in range(10)]
    messages[2]["content"] = [{"type": "image", "source": {
        "type": "base64", "media_type": "image/png", "data": ""}},
        {"type": "text", "text": "api | requires | token"}]
    return messages


class _LLM:
    model = "test:local-seam"

    def __init__(self, error=None, delay=False):
        self.error = error
        self.delay = delay
        self.calls = []
        self.sync_calls = []
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cancelled = False

    def complete(self, **kwargs):
        self.sync_calls.append(kwargs)
        if self.error:
            raise self.error
        return SimpleNamespace(text="api | requires | token")

    async def complete_async(self, **kwargs):
        self.calls.append(kwargs)
        self.started.set()
        try:
            if self.delay:
                await self.release.wait()
            if self.error:
                raise self.error
            return SimpleNamespace(text="api | requires | token")
        except asyncio.CancelledError:
            self.cancelled = True
            raise


@pytest.mark.asyncio
@pytest.mark.parametrize("strategy", STRATEGIES)
async def test_sync_async_output_request_and_budget_parity(strategy):
    source = _history()
    snapshot = copy.deepcopy(source)
    llm = _LLM()
    budget = Budget(max_dollars=1)
    expected = compact_with_strategy(source, strategy=strategy, llm=llm, budget=budget,
                                     conversation_id="sync-parity", keep_recent=2)
    actual = await compact_with_strategy_async(
        source, strategy=strategy, llm=llm, budget=budget,
        conversation_id="async-parity", keep_recent=2)
    assert actual == expected
    assert len(llm.calls) == len(llm.sync_calls) >= 1
    assert llm.calls == llm.sync_calls
    assert all(call["budget"] is budget for call in llm.calls)
    assert source == snapshot


@pytest.mark.asyncio
@pytest.mark.parametrize("strategy", STRATEGIES)
async def test_provider_wait_yields_to_heartbeat_and_cancel_stops_work(strategy):
    llm = _LLM(delay=True)
    task = asyncio.create_task(compact_with_strategy_async(
        _history(), strategy=strategy, llm=llm, conversation_id="cancel", keep_recent=2))
    await asyncio.wait_for(llm.started.wait(), 1)
    ticks = []
    for index in range(3):
        await asyncio.sleep(0)
        ticks.append(index)
    assert ticks == [0, 1, 2] and not task.done()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert llm.cancelled and len(llm.calls) == 1 and not llm.sync_calls


@pytest.mark.asyncio
@pytest.mark.parametrize("strategy", STRATEGIES)
@pytest.mark.parametrize("error", [BudgetExceeded("stop"), UsageAccountingError("stop"),
                                  killswitch.Halted("stop", "test")])
async def test_control_errors_never_fall_back_or_replay(strategy, error):
    llm = _LLM(error=error)
    with pytest.raises(type(error)):
        await cp.compact_with_async(_history(), strategy=strategy, llm=llm,
                                    conversation_id="stop", keep_recent=2)
    assert len(llm.calls) == 1 and not llm.sync_calls
    with pytest.raises(type(error)):
        cp.compact_with(_history(), strategy=strategy, llm=llm,
                        conversation_id="stop-sync", keep_recent=2)
    assert len(llm.sync_calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("strategy", STRATEGIES)
async def test_ordinary_provider_failure_is_deterministic(strategy):
    llm = _LLM(error=RuntimeError("offline provider seam"))
    expected = compact_with_strategy(_history(), strategy=strategy, llm=None,
                                     conversation_id="heuristic", keep_recent=2)
    actual = await compact_with_strategy_async(_history(), strategy=strategy, llm=llm,
                                               conversation_id="failure", keep_recent=2)
    assert actual == expected and len(llm.calls) == 1 and not llm.sync_calls


@pytest.mark.asyncio
async def test_sync_only_seam_and_plugin_cannot_block_async_loop(monkeypatch):
    class SyncOnly:
        name = "sync-only"
        def complete(self, **kwargs):
            pytest.fail("sync provider must not run")
        def compact(self, messages, **kwargs):
            pytest.fail("sync plugin must not run")
    seam = SyncOnly()
    source = _history()
    monkeypatch.setitem(cp._REGISTRY, seam.name, seam)
    expected = compact_messages(source, keep_recent=2)
    assert await cp.compact_with_async(source, strategy=seam.name, keep_recent=2) == expected
    assert await cp.compact_with_async(source, strategy="learned", llm=seam,
                                       keep_recent=2) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("strategy", ("learned", "streaming", "graph"))
async def test_digest_preserves_pair_crossing_recent_boundary(strategy):
    source = _history()
    source[-3] = {"role": "assistant", "content": [
        {"type": "tool_use", "id": "call", "name": "lookup", "input": {}}]}
    source[-2] = {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "call", "content": "answer"}]}
    out = await compact_with_strategy_async(source, strategy=strategy, llm=_LLM(),
                                             conversation_id="pair", keep_recent=2)
    assert out[0] == source[0] and out[-3:] == source[-3:]
    assert len(out) < len(source)


@pytest.mark.asyncio
@pytest.mark.parametrize("strategy", ("learned", "streaming", "graph"))
async def test_first_message_exchange_declines_digest_without_provider_call(strategy):
    source = _history()
    source[0] = {"role": "assistant", "content": [
        {"type": "tool_use", "id": "first", "name": "lookup", "input": {}}]}
    source[1] = {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "first", "content": "answer"}]}
    llm = _LLM()
    assert await compact_with_strategy_async(source, strategy=strategy, llm=llm,
                                               keep_recent=2) == source
    assert not llm.calls


@pytest.mark.asyncio
async def test_async_plugin_precedence_and_hybrid_outcomes(monkeypatch):
    class Strategy:
        name = "async-marker"
        def compact(self, messages, **kwargs):
            pytest.fail("sync dispatch")
        async def compact_async(self, messages, **kwargs):
            return [{"role": "user", "content": "marker"}]
    marker = Strategy()
    monkeypatch.setitem(cp._REGISTRY, marker.name, marker)
    monkeypatch.setattr(cp, "_configured_name", lambda: marker.name)
    monkeypatch.setenv("MAVERICK_COMPACTION_HYBRID", "1")
    source = [{"role": "user", "content": "x" * 20_000}]
    assert await cp.compact_with_async(source) == [{"role": "user", "content": "marker"}]
    assert await cp.compact_with_async(source, strategy="heuristic") == compact_messages(source)
    records = []
    picker = SimpleNamespace(pick=lambda messages: ("summarize", "test"),
                             record=lambda *args, **kwargs: records.append(kwargs))
    monkeypatch.setattr(cp, "_configured_name", lambda: "")
    monkeypatch.setattr(cp, "_hybrid_picker", lambda: picker)
    monkeypatch.setitem(cp._REGISTRY, "learned", marker)
    assert await cp.compact_with_async(source) == [{"role": "user", "content": "marker"}]
    assert records == [{"success": True}]


@pytest.mark.asyncio
@pytest.mark.parametrize("stop", ("halt", "wall", "budget", "accounting", "cancel"))
async def test_real_agent_stops_during_compaction_before_primary_request(tmp_path, monkeypatch, stop):
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    llm = _LLM(delay=True)
    # An in-run digest waits for its turn interval unless the history is over
    # the byte ceiling; a tiny ceiling makes the first turn digest the history.
    monkeypatch.setenv("MAVERICK_COMPACT_MAX_TOTAL_BYTES", "1")
    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("compaction guard regression", "")
    budget = Budget(max_dollars=1, max_wall_seconds=30)
    ctx = SwarmContext(llm=llm, world=world, budget=budget, blackboard=Blackboard(),
                       sandbox=LocalBackend(workdir=tmp_path), goal_id=goal_id,
                       max_depth=2, use_skills=False)
    agent = Agent(ctx=ctx, role="researcher", brief="test guard")
    monkeypatch.setattr(agent, "_HALT_POLL_SECONDS", 0.01)
    # Only inject pre-existing source history. Run real dispatch, native async
    # strategy, wall/halt guard, and AgentResult stop translation.
    monkeypatch.setattr(agent, "_resume_from_checkpoint", lambda *args: (None, 0, _history()))
    monkeypatch.setenv("MAVERICK_COMPACTION_STRATEGY", "learned")
    if stop == "wall":
        budget.max_wall_seconds = 0.25
        budget._started_monotonic = time.monotonic()
    task = asyncio.create_task(agent.run())
    try:
        await asyncio.wait_for(llm.started.wait(), 2)
        assert len(llm.calls) == 1 and "Summarize" in llm.calls[0]["system"]
        if stop == "halt":
            killswitch.halt("test compaction halt", source="test")
        elif stop == "wall":
            pass  # The real wall deadline expires while the provider is waiting.
        elif stop in {"budget", "accounting"}:
            llm.error = (BudgetExceeded("test compaction budget") if stop == "budget"
                         else UsageAccountingError("test compaction accounting"))
            llm.release.set()
        else:
            task.cancel()
        if stop == "cancel":
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            result = await asyncio.wait_for(task, 2)
            assert result.error
            assert result.stop_kind != "completed"
        assert len(llm.calls) == 1 and not llm.sync_calls
        if stop in {"halt", "wall", "cancel"}:
            assert llm.cancelled
    finally:
        killswitch.clear()
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        world.close()


@pytest.mark.asyncio
async def test_halt_between_media_calls_prevents_second_request():
    class HaltAfterFirst(_LLM):
        async def complete_async(self, **kwargs):
            response = await super().complete_async(**kwargs)
            killswitch.halt("stop between descriptions", source="test")
            return response
    source = _history()
    source[2]["content"].append(copy.deepcopy(source[2]["content"][0]))
    llm = HaltAfterFirst()
    try:
        with pytest.raises(killswitch.Halted):
            await compact_with_strategy_async(source, strategy="multimodal", llm=llm,
                                               keep_recent=2)
        assert len(llm.calls) == 1 and not llm.sync_calls
    finally:
        killswitch.clear()


@pytest.mark.asyncio
async def test_streaming_out_of_order_completion_cannot_overwrite_new_cursor(tmp_path):
    from maverick.compaction.streaming import StreamingCompactor
    path = tmp_path / "stream.json"
    old_llm, new_llm = _LLM(delay=True), _LLM(delay=True)
    old = StreamingCompactor(llm=old_llm, path=path)
    new = StreamingCompactor(llm=new_llm, path=path)
    source = _history()
    old_task = asyncio.create_task(old.fold_async("same", source[:2]))
    await asyncio.wait_for(old_llm.started.wait(), 1)
    new_task = asyncio.create_task(new.fold_async("same", source[:4]))
    await asyncio.wait_for(new_llm.started.wait(), 1)
    new_llm.release.set()
    await new_task
    old_llm.release.set()
    await old_task
    assert new.state("same")[0] == 4
    await new.fold_async("same", source[:4])
    assert len(new_llm.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ("reset", "cancel"))
async def test_streaming_reset_or_cancel_cannot_commit_stale_fold(tmp_path, action):
    from maverick.compaction.streaming import StreamingCompactor
    path = tmp_path / "stream.json"
    source = _history()
    StreamingCompactor(path=path).fold("same", source[:2])
    llm = _LLM(delay=True)
    compactor = StreamingCompactor(llm=llm, path=path)
    task = asyncio.create_task(compactor.fold_async("same", source[:4]))
    await asyncio.wait_for(llm.started.wait(), 1)
    if action == "reset":
        compactor.reset("same")
        llm.release.set()
        await task
        assert compactor.state("same") == (0, "")
    else:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert compactor.state("same")[0] == 2
