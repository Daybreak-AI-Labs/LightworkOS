"""The LLM await is interruptible: the wall-clock cap and the killswitch now
abort an in-flight generation instead of only being checked at turn boundaries."""
from __future__ import annotations

import asyncio
import types

import pytest
from maverick import killswitch
from maverick.agent import Agent
from maverick.budget import Budget, BudgetExceeded


class _FakeLLM:
    def __init__(self, delay: float):
        self.delay = delay
        self.cancelled = False
        self.completed = False

    async def complete_async(self, **kw):
        try:
            await asyncio.sleep(self.delay)
            self.completed = True
            return "RESPONSE"
        except asyncio.CancelledError:
            self.cancelled = True
            raise


def _agent(budget: Budget, llm: _FakeLLM):
    # Duck-typed stand-in: _complete_guarded only touches self.ctx.budget,
    # self.ctx.llm, self._HALT_POLL_SECONDS, and (via the shared guard)
    # self._await_wall_clock_guarded -- bind the real method so the shared
    # wall-clock/killswitch polling loop it delegates to actually runs.
    obj = types.SimpleNamespace(
        ctx=types.SimpleNamespace(budget=budget, llm=llm),
        _HALT_POLL_SECONDS=0.02,
    )
    obj._await_wall_clock_guarded = Agent._await_wall_clock_guarded.__get__(obj)
    return obj


def test_returns_normally_when_fast():
    llm = _FakeLLM(delay=0.0)
    obj = _agent(Budget(max_wall_seconds=30), llm)
    assert asyncio.run(Agent._complete_guarded(obj)) == "RESPONSE"


def test_wall_cap_aborts_inflight_generation():
    llm = _FakeLLM(delay=5.0)
    obj = _agent(Budget(max_wall_seconds=0.05), llm)
    with pytest.raises(BudgetExceeded):
        asyncio.run(Agent._complete_guarded(obj))
    assert llm.cancelled and not llm.completed


def test_killswitch_aborts_inflight_generation():
    llm = _FakeLLM(delay=5.0)
    obj = _agent(Budget(max_wall_seconds=30), llm)

    async def _drive():
        task = asyncio.ensure_future(Agent._complete_guarded(obj))
        await asyncio.sleep(0.05)
        killswitch.halt("test halt", source="test")  # trip mid-generation
        return await task

    try:
        with pytest.raises(killswitch.Halted):
            asyncio.run(_drive())
        assert llm.cancelled and not llm.completed
    finally:
        killswitch.clear()


def test_already_over_wall_raises_before_call():
    llm = _FakeLLM(delay=0.0)
    b = Budget(max_wall_seconds=1.0)
    # Force elapsed past the cap.
    import time
    b._started_monotonic = time.monotonic() - 5.0
    obj = _agent(b, llm)
    with pytest.raises(BudgetExceeded):
        asyncio.run(Agent._complete_guarded(obj))
    assert not llm.completed  # never started the call
