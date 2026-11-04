"""Tail-latency hedging in LLM.complete_async (opt-in, default OFF).

When [latency] hedge_ms / MAVERICK_LLM_HEDGE_MS is set, the async path fires a
backup request after the delay and takes whichever succeeds first, cancelling the
laggard. Off by default the single-call path is unchanged.
"""
from __future__ import annotations

import asyncio

import pytest
from maverick import llm as llm_mod
from maverick.llm import LLM, LLMResponse

OPUS = "claude-opus-4-8"


def _resp(text: str) -> LLMResponse:
    return LLMResponse(text=text, thinking=None, tool_calls=[], stop_reason="end_turn")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("MAVERICK_LLM_HEDGE_MS", raising=False)
    # No config -> hedge resolves from env only.
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def test_hedge_off_by_default():
    assert llm_mod._hedge_ms() is None


def test_hedge_reads_env_and_config(monkeypatch):
    monkeypatch.setenv("MAVERICK_LLM_HEDGE_MS", "250")
    assert llm_mod._hedge_ms() == 250.0
    monkeypatch.setenv("MAVERICK_LLM_HEDGE_MS", "0")  # non-positive disables
    assert llm_mod._hedge_ms() is None
    monkeypatch.delenv("MAVERICK_LLM_HEDGE_MS")
    monkeypatch.setattr(
        "maverick.config.load_config", lambda *a, **k: {"latency": {"hedge_ms": 50}}
    )
    assert llm_mod._hedge_ms() == 50.0


def test_no_hedge_calls_provider_once(monkeypatch):
    calls = []

    class FakeClient:
        async def complete_async(self, **kwargs):
            calls.append(1)
            return _resp("ok")

    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: FakeClient())

    out = asyncio.run(
        LLM(model=OPUS).complete_async("sys", [{"role": "user", "content": "hi"}])
    )
    assert out.text == "ok"
    assert len(calls) == 1


def test_hedge_backup_wins_when_primary_is_slow(monkeypatch):
    monkeypatch.setenv("MAVERICK_LLM_HEDGE_MS", "10")

    class FakeClient:
        def __init__(self):
            self.n = 0

        async def complete_async(self, **kwargs):
            self.n += 1
            if self.n == 1:  # primary: slow, should be cancelled
                await asyncio.sleep(5.0)
                return _resp("primary")
            await asyncio.sleep(0.01)  # backup: quick
            return _resp("backup")

    client = FakeClient()
    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: client)

    out = asyncio.run(
        LLM(model=OPUS).complete_async("sys", [{"role": "user", "content": "hi"}])
    )
    assert out.text == "backup"


def test_hedge_both_fail_surfaces_provider_error(monkeypatch):
    monkeypatch.setenv("MAVERICK_LLM_HEDGE_MS", "5")

    class FakeClient:
        async def complete_async(self, **kwargs):
            raise RuntimeError("provider down")

    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: FakeClient())

    async def run():
        return await LLM(model=OPUS).complete_async(
            "sys", [{"role": "user", "content": "hi"}]
        )

    # The real provider error is surfaced, not the race's AllAttemptsFailed wrapper.
    with pytest.raises(RuntimeError, match="provider down"):
        asyncio.run(run())


def test_hedge_race_bounded_by_wall_budget(monkeypatch):
    monkeypatch.setenv("MAVERICK_LLM_HEDGE_MS", "10")
    from maverick.budget import Budget

    class FakeClient:
        async def complete_async(self, **kwargs):
            await asyncio.sleep(5.0)  # never returns within the wall budget
            return _resp("late")

    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: FakeClient())
    budget = Budget(max_dollars=1.0, max_wall_seconds=0.1)

    async def run():
        return await LLM(model=OPUS).complete_async(
            "sys", [{"role": "user", "content": "hi"}], budget=budget
        )

    # SpanBudget caps the race at the remaining wall budget -> TimeoutError.
    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(run())


def test_hedge_race_with_exhausted_wall_budget_times_out(monkeypatch):
    """A wall budget that is already spent bounds the race at zero. This is
    the deterministic form of the race-bounded-by-wall-budget case: on a slow
    runner the 100ms wall can elapse before the race starts, and an exhausted
    span must yield an immediate TimeoutError, never an unbounded race."""
    monkeypatch.setenv("MAVERICK_LLM_HEDGE_MS", "10")
    import time

    from maverick.budget import Budget

    class FakeClient:
        async def complete_async(self, **kwargs):
            await asyncio.sleep(5.0)  # would win any unbounded race
            return _resp("late")

    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: FakeClient())
    budget = Budget(max_dollars=1.0, max_wall_seconds=0.05)
    time.sleep(0.06)  # burn the whole wall before the race starts

    async def run():
        return await LLM(model=OPUS).complete_async(
            "sys", [{"role": "user", "content": "hi"}], budget=budget
        )

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(run())


def test_hedge_backup_requires_its_own_budget_reservation(monkeypatch):
    monkeypatch.setenv("MAVERICK_LLM_HEDGE_MS", "10")
    from maverick.budget import Budget

    est_cost = llm_mod._estimate_call_cost(
        OPUS, "sys", [{"role": "user", "content": "hi"}], None, 4096
    )
    dispatches = 0

    class FakeClient:
        async def complete_async(self, **kwargs):
            nonlocal dispatches
            dispatches += 1
            await asyncio.sleep(0.05)
            return _resp("primary")

    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: FakeClient())
    budget = Budget(max_dollars=est_cost * 1.5, max_wall_seconds=1.0)

    out = asyncio.run(
        LLM(model=OPUS).complete_async(
            "sys", [{"role": "user", "content": "hi"}], budget=budget
        )
    )

    assert out.text == "primary"
    assert dispatches == 1
    assert getattr(budget, "_reserved", 0.0) == 0.0
