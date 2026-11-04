"""Latency-aware best-of-N (re-triage build)."""
from __future__ import annotations

import asyncio

import pytest
from maverick.latency_best_of_n import AllAttemptsFailed, race_first_success


def test_first_success_wins_and_cancels_slow():
    completed: list[str] = []

    async def fast():
        await asyncio.sleep(0.01)
        completed.append("fast")
        return "fast-result"

    async def slow():
        await asyncio.sleep(5.0)
        completed.append("slow")  # should never run — cancelled
        return "slow-result"

    out = asyncio.run(race_first_success([fast, slow]))
    assert out == "fast-result"
    assert "slow" not in completed  # the laggard was cancelled


def test_fast_failure_does_not_win():
    async def fast_fail():
        await asyncio.sleep(0.01)
        raise RuntimeError("boom")

    async def slower_success():
        await asyncio.sleep(0.05)
        return "ok"

    assert asyncio.run(race_first_success([fast_fail, slower_success])) == "ok"


def test_all_fail_raises():
    async def boom():
        raise ValueError("nope")

    with pytest.raises(AllAttemptsFailed):
        asyncio.run(race_first_success([boom, boom]))


def test_budget_timeout():
    async def slow():
        await asyncio.sleep(5.0)
        return "x"

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(race_first_success([slow], budget_ms=20))


def test_empty_factories_rejected():
    with pytest.raises(ValueError):
        asyncio.run(race_first_success([]))


def test_success_within_budget():
    async def quick():
        await asyncio.sleep(0.01)
        return 42

    assert asyncio.run(race_first_success([quick], budget_ms=1000)) == 42
