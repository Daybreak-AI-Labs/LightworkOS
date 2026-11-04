"""Speculative / overlapped execution primitive."""
from __future__ import annotations

import asyncio

import pytest
from maverick.speculative import Speculation, run_independent, speculate


class TestSpeculation:
    @pytest.mark.asyncio
    async def test_runs_eagerly_and_returns_result(self):
        started = asyncio.Event()

        async def work():
            started.set()
            await asyncio.sleep(0)
            return 42

        spec = speculate(work())
        # Yield control: the task should run without us awaiting result yet.
        await asyncio.sleep(0)
        assert started.is_set()
        assert await spec.result() == 42

    @pytest.mark.asyncio
    async def test_result_is_cached_and_idempotent(self):
        calls = {"n": 0}

        async def work():
            calls["n"] += 1
            return "v"

        spec = speculate(work())
        assert await spec.result() == "v"
        assert await spec.result() == "v"
        assert calls["n"] == 1

    @pytest.mark.asyncio
    async def test_result_reraises_exception(self):
        async def boom():
            raise ValueError("nope")

        spec = speculate(boom())
        with pytest.raises(ValueError, match="nope"):
            await spec.result()

    @pytest.mark.asyncio
    async def test_speculations_run_concurrently(self):
        # Prove overlap STRUCTURALLY, not via wall-clock: a timing bound
        # (elapsed < 0.18s) is flaky under loaded CI runners. Both tasks must
        # be in-flight simultaneously -- each signals on entry, then waits on a
        # shared release that is only set once BOTH have started. If speculate
        # ran them sequentially, the second would never start (the first is
        # parked on release), so awaiting both 'started' events would time out.
        started = [asyncio.Event(), asyncio.Event()]
        release = asyncio.Event()

        async def task(i, v):
            started[i].set()
            await release.wait()
            return v

        a = speculate(task(0, "a"))
        b = speculate(task(1, "b"))
        await asyncio.wait_for(
            asyncio.gather(started[0].wait(), started[1].wait()), timeout=1.0,
        )
        release.set()
        assert (await a.result(), await b.result()) == ("a", "b")

    @pytest.mark.asyncio
    async def test_cancel_is_safe_before_and_after_done(self):
        async def slow():
            await asyncio.sleep(10)
            return "never"

        spec = speculate(slow())
        await spec.cancel()
        assert spec.done is True
        # Second cancel is a no-op, does not raise.
        await spec.cancel()

    @pytest.mark.asyncio
    async def test_cancel_after_completion_noop(self):
        spec = speculate(asyncio.sleep(0, result="done"))
        assert await spec.result() == "done"
        await spec.cancel()  # already finished -> no-op


class TestRunIndependent:
    @pytest.mark.asyncio
    async def test_empty_returns_empty(self):
        assert await run_independent() == []

    @pytest.mark.asyncio
    async def test_all_run_and_return_in_order(self):
        async def v(x):
            return x

        assert await run_independent(v(1), v(2), v(3)) == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_one_failure_does_not_abort_others(self):
        ran = {"a": False, "c": False}

        async def a():
            ran["a"] = True
            return "a"

        async def b():
            raise RuntimeError("b failed")

        async def c():
            ran["c"] = True
            return "c"

        results = await run_independent(a(), b(), c())
        assert ran["a"] and ran["c"]
        assert results[0] == "a"
        assert isinstance(results[1], RuntimeError)
        assert results[2] == "c"

    @pytest.mark.asyncio
    async def test_swallow_false_raises(self):
        async def boom():
            raise ValueError("x")

        with pytest.raises(ValueError):
            await run_independent(boom(), swallow_errors=False)


class TestType:
    def test_speculate_returns_speculation(self):
        async def _build():
            spec = speculate(asyncio.sleep(0))
            assert isinstance(spec, Speculation)
            await spec.result()

        asyncio.run(_build())
