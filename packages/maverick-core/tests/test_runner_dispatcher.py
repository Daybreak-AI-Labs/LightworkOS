"""Goal-execution dispatcher seam (threads now, queue later).

``run_goal_in_background`` routes through a swappable Dispatcher so a future
queue/worker backend is a ``set_dispatcher`` call, not a caller rewrite.
"""
from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

import maverick.runner as runner
import pytest


def test_default_dispatcher_is_local_thread():
    assert isinstance(runner.get_dispatcher(), runner.LocalThreadDispatcher)


def test_run_goal_in_background_delegates_to_active_dispatcher(monkeypatch):
    calls = []

    class FakeDispatcher:
        def submit(self, goal_id, **kw):
            calls.append((goal_id, kw))
            return "done"

    monkeypatch.setattr(runner, "_dispatcher", FakeDispatcher())
    out = runner.run_goal_in_background(
        7, max_dollars=2.0, channel="api", user_id="u1", conversation_id=19,
        allowed_suites=frozenset({"finance"}),
    )
    assert out == "done"
    assert calls[0][0] == 7
    assert calls[0][1]["max_dollars"] == 2.0
    assert calls[0][1]["channel"] == "api"
    assert calls[0][1]["user_id"] == "u1"
    assert calls[0][1]["conversation_id"] == 19
    assert calls[0][1]["allowed_suites"] == frozenset({"finance"})


@pytest.mark.asyncio
async def test_async_dispatcher_wrapper_runs_submission_off_event_loop(monkeypatch):
    calls = []
    event_loop_thread = threading.get_ident()

    class FakeDispatcher:
        def submit(self, goal_id, **kw):
            calls.append((threading.get_ident(), goal_id, kw))
            return "done"

    monkeypatch.setattr(runner, "_dispatcher", FakeDispatcher())
    out = await runner.run_goal_in_background_async(
        8, channel="telegram", user_id="alice", conversation_id=23,
        allowed_suites=frozenset(),
    )

    assert out == "done"
    assert calls[0][0] != event_loop_thread
    assert calls[0][1] == 8
    assert calls[0][2]["conversation_id"] == 23
    assert calls[0][2]["allowed_suites"] == frozenset()


@pytest.mark.asyncio
async def test_cancelling_async_waiter_does_not_stop_started_dispatch(monkeypatch):
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    class BlockingDispatcher:
        def submit(self, goal_id, **kwargs):
            started.set()
            try:
                if not release.wait(timeout=5):
                    raise TimeoutError("test did not release dispatcher")
                return "done"
            finally:
                finished.set()

    monkeypatch.setattr(runner, "_dispatcher", BlockingDispatcher())
    task = asyncio.create_task(runner.run_goal_in_background_async(9))
    try:
        assert await asyncio.to_thread(started.wait, 3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not finished.is_set()
    finally:
        release.set()
    assert await asyncio.to_thread(finished.wait, 3)


@pytest.mark.asyncio
@pytest.mark.parametrize("dispatcher_result", [None, RuntimeError("broker down")])
async def test_unknown_dispatch_does_not_block_pending_goal_or_fall_back(
    monkeypatch, dispatcher_result,
):
    from maverick import world_model

    updates = []

    class FakeWorld:
        def get_goal(self, goal_id):
            return SimpleNamespace(status="pending")

        def block_pending_goal(self, goal_id, *, result):
            updates.append((goal_id, "blocked", result))
            return True

    class FailingDispatcher:
        def submit(self, goal_id, **kw):
            if isinstance(dispatcher_result, Exception):
                raise dispatcher_result
            return dispatcher_result

    monkeypatch.setattr(runner, "_dispatcher", FailingDispatcher())
    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda *a, **k: pytest.fail("dispatch failure fell back to local execution"),
    )
    monkeypatch.setattr(world_model, "open_world", lambda: FakeWorld())
    monkeypatch.setattr(world_model, "close_world_if_owned", lambda world: None)

    out = await runner.run_goal_in_background_async(41)

    assert out == ("error" if isinstance(dispatcher_result, Exception) else None)
    assert updates == []


@pytest.mark.asyncio
async def test_definitive_nonacceptance_does_not_overwrite_other_submissions(monkeypatch):
    from maverick import world_model

    updates = []

    class FakeWorld:
        def block_pending_goal(self, goal_id, *, result):
            updates.append((goal_id, result))
            return True

    class RejectedDispatcher:
        def submit_observed(self, goal_id, **kw):
            return runner.DispatchObservation(
                goal_id, runner.DispatchState.NOT_ACCEPTED, None,
                reason="test_preflight",
            )

        def submit(self, goal_id, **kw):
            pytest.fail("structured adapter must be called only once")

    monkeypatch.setattr(runner, "_dispatcher", RejectedDispatcher())
    monkeypatch.setattr(world_model, "open_world", lambda: FakeWorld())
    monkeypatch.setattr(world_model, "close_world_if_owned", lambda world: None)
    assert await runner.run_goal_in_background_async(41) is None
    assert updates == []


def test_local_dispatcher_delegates_to_run_goal_in_thread(monkeypatch):
    seen = {}

    def fake_run(*, goal_id, **kw):
        seen["goal_id"] = goal_id
        seen.update(kw)
        return "blocked"

    monkeypatch.setattr(runner, "run_goal_in_thread", fake_run)
    out = runner.LocalThreadDispatcher().submit(
        42, max_wall_seconds=30.0, conversation_id=17,
        allowed_suites=frozenset({"legal"}),
    )
    assert out == "blocked"
    assert seen["goal_id"] == 42
    assert seen["max_wall_seconds"] == 30.0
    assert seen["conversation_id"] == 17
    assert seen["allowed_suites"] == frozenset({"legal"})


def test_set_dispatcher_swaps_and_is_restorable():
    original = runner.get_dispatcher()
    try:
        sentinel = runner.LocalThreadDispatcher()
        runner.set_dispatcher(sentinel)
        assert runner.get_dispatcher() is sentinel
    finally:
        runner.set_dispatcher(original)
    assert runner.get_dispatcher() is original


# ---------- goal execution must not share the loop's default pool ----------

def test_default_asyncio_executor_is_undersized_for_the_advertised_ceiling():
    """Documents the defect precondition this fix closes: CPython's default
    ThreadPoolExecutor (what asyncio.to_thread uses) is sized off CPU count,
    not off MAX_CONCURRENT_GOALS -- on anything with <=12 cores it is smaller
    than the advertised ceiling of 16, so the ceiling was silently
    unreachable when goal runs shared that pool."""
    import os

    default_executor_size = min(32, (os.cpu_count() or 1) + 4)
    assert default_executor_size < runner.MAX_CONCURRENT_GOALS or os.cpu_count() > 12


def test_goal_executor_capacity_covers_max_concurrent_goals():
    """The dedicated pool must be able to run MAX_CONCURRENT_GOALS goals at
    once regardless of host core count -- the whole point of not sharing the
    default executor."""
    assert runner._goal_executor._max_workers >= runner.MAX_CONCURRENT_GOALS


@pytest.mark.asyncio
async def test_async_dispatch_uses_the_dedicated_goal_executor(monkeypatch):
    """Regression: run_goal_in_background_async must submit to _goal_executor,
    not asyncio.to_thread's shared default pool."""

    class FakeDispatcher:
        def submit(self, goal_id, **kw):
            return "done"

    monkeypatch.setattr(runner, "_dispatcher", FakeDispatcher())

    calls = []
    real_submit = runner._goal_executor.submit

    def spying_submit(fn, *a, **kw):
        calls.append(1)
        return real_submit(fn, *a, **kw)

    monkeypatch.setattr(runner._goal_executor, "submit", spying_submit)

    out = await runner.run_goal_in_background_async(9)
    assert out == "done"
    assert calls == [1]


@pytest.mark.asyncio
async def test_context_propagates_across_the_dedicated_executor(monkeypatch):
    """Regression: switching from asyncio.to_thread (which copies the
    caller's contextvars.Context into the worker thread) to a custom
    loop.run_in_executor call must not silently drop that propagation --
    e.g. the active-tenant contextvar must still be visible inside the
    threaded dispatcher call."""
    import contextvars

    probe: contextvars.ContextVar[str] = contextvars.ContextVar("w1_72_probe")
    seen = {}

    class FakeDispatcher:
        def submit(self, goal_id, **kw):
            seen["value"] = probe.get("MISSING")
            return "done"

    monkeypatch.setattr(runner, "_dispatcher", FakeDispatcher())

    token = probe.set("tenant-42")
    try:
        out = await runner.run_goal_in_background_async(10)
    finally:
        probe.reset(token)

    assert out == "done"
    assert seen["value"] == "tenant-42"
