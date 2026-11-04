"""Deterministic stream cadence, backpressure, replay and slot ownership."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from maverick.goal_views import GoalStreamState
from maverick_dashboard import _event_stream as streams


class Clock:
    now = 0.0

    async def sleep(self, seconds):
        self.now += seconds


class Request:
    disconnected = False

    async def is_disconnected(self):
        return self.disconnected


class World:
    def __init__(self, clock):
        self.clock = clock
        self.reads = []
        self.status = "active"
        self.owner = "alice"
        self.events = []

    def goal_stream_state(self, goal_id, *, include_result=False):
        self.reads.append(("state", include_result))
        if self.status is None:
            return None
        return GoalStreamState(goal_id, self.status, self.owner, "safe result" if include_result else "")

    def goal_events(self, goal_id, *, since_id, limit):
        self.reads.append(("events", since_id))
        return [event for event in self.events if event.id > since_id][:limit]


@pytest.fixture(autouse=True)
def local_reads(monkeypatch):
    async def call(function, *args, **kwargs):
        return function(*args, **kwargs)
    monkeypatch.setattr(streams, "run_in_threadpool", call)


@pytest.mark.parametrize("legacy", [False, True])
def test_idle_heartbeat_keeps_monotonic_deadlines_through_backoff(legacy):
    async def run():
        clock, request = Clock(), Request()
        world = World(clock)
        sem = asyncio.Semaphore(1)
        await sem.acquire()
        lease = streams.StreamLease(sem)
        ticks = []
        stream = streams.goal_stream(request, world, 1, since=0, lease=lease,
                                     visible=lambda _state: True, legacy=legacy,
                                     clock=lambda: clock.now, sleep=clock.sleep, lifetime=65)
        async for frame in stream:
            if "heartbeat" in frame:
                ticks.append(clock.now)
        assert ticks == [30.0, 60.0]
        assert clock.now == 65 and not sem.locked()
        # Legacy frames include live answer previews even without event rows;
        # the modern event-only stream keeps its result-free projection.
        state_reads = [result for kind, result in world.reads if kind == "state"]
        assert state_reads and all(result is legacy for result in state_reads)
    asyncio.run(run())


@pytest.mark.parametrize("legacy", [False, True])
def test_replay_drains_terminal_batches_and_preserves_wire_format(legacy):
    async def run():
        clock, request = Clock(), Request()
        world = World(clock)
        world.status = "done"
        world.events = [SimpleNamespace(id=i, agent="worker", kind="step", content=f"event-{i}", ts=i)
                        for i in range(1, 8)]
        sem = asyncio.Semaphore(1)
        await sem.acquire()
        stream = streams.goal_stream(request, world, 1, since=3, lease=streams.StreamLease(sem),
                                     visible=lambda _state: True, legacy=legacy, max_batch=2,
                                     clock=lambda: clock.now, sleep=clock.sleep)
        frames = [frame async for frame in stream]
        body = "".join(frames)
        assert "event-3" not in body and all(f"event-{i}" in body for i in range(4, 8))
        assert ("event: terminal" if legacy else "event: end") in frames[-1]
        assert ("safe result" in body) is legacy
        assert clock.now == 0 and not sem.locked()
    asyncio.run(run())


def test_backpressure_disconnect_and_vanished_or_denied_state_do_not_prefetch():
    async def run():
        for state in (None, "foreign", "disconnected"):
            clock, request = Clock(), Request()
            world = World(clock)
            sem = asyncio.Semaphore(1)
            await sem.acquire()
            stream = streams.goal_stream(request, world, 1, since=0, lease=streams.StreamLease(sem),
                                         visible=lambda value: value.owner == "alice")
            assert await anext(stream) == ": connected\n\n"
            assert world.reads == []  # consumer has not asked for another frame
            if state is None:
                world.status = None
            elif state == "foreign":
                world.owner = "bob"
            else:
                request.disconnected = True
            frames = [frame async for frame in stream]
            assert all(kind != "events" for kind, _value in world.reads)
            assert not sem.locked()
            assert frames == [] if state == "disconnected" else "goal vanished" in frames[0]
    asyncio.run(run())


def test_cancel_during_idle_wait_releases_exactly_one_slot():
    async def run():
        waiting = asyncio.Event()

        async def blocked(_seconds):
            waiting.set()
            await asyncio.Future()

        sem = asyncio.Semaphore(1)
        await sem.acquire()
        lease = streams.StreamLease(sem)
        stream = streams.goal_stream(Request(), World(Clock()), 1, since=0, lease=lease,
                                     visible=lambda _state: True, sleep=blocked)
        await anext(stream)
        task = asyncio.create_task(anext(stream))
        await waiting.wait()
        task.cancel()
        with pytest.raises(StopAsyncIteration):
            await task
        lease.release()  # response finally is also allowed to release
        await sem.acquire()
        assert sem.locked()
    asyncio.run(run())


def test_response_cancel_before_iterator_starts_releases_slot(monkeypatch):
    async def run():
        async def interrupted(*_args):
            raise asyncio.CancelledError
        monkeypatch.setattr(streams.StreamingResponse, "__call__", interrupted)
        sem = asyncio.Semaphore(1)
        await sem.acquire()
        lease = streams.StreamLease(sem)
        stream = streams.goal_stream(Request(), World(Clock()), 1, since=0, lease=lease,
                                     visible=lambda _state: True)
        response = streams.LeasedStreamingResponse(stream, lease=lease)
        with pytest.raises(asyncio.CancelledError):
            await response({}, None, None)
        assert not sem.locked()
        await stream.aclose()
    asyncio.run(run())


def test_a_committed_change_ends_the_wait_and_the_stream_stops_watching(tmp_path, monkeypatch):
    """The poll backed off to two seconds while a model call ran, so a finished
    answer reached the page about 1.2 s after it was saved. A write in this
    process now ends the wait; the database read after it decides the frame."""
    import threading
    import time

    from maverick import goal_wakeup, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    world = world_model.WorldModel(tmp_path / "w.db")
    gid = world.create_goal("task", "")

    async def run():
        sem = asyncio.Semaphore(1)
        await sem.acquire()
        lease = streams.StreamLease(sem)
        # A thirty-second poll: only a wake-up can deliver the event in time.
        stream = streams.goal_stream(Request(), world, gid, since=0, lease=lease,
                                     visible=lambda _state: True, poll=30.0, max_poll=30.0,
                                     heartbeat=60.0)
        assert (await stream.__anext__()).startswith(": connected")
        writer = threading.Timer(0.3, lambda: world.append_event(gid, "agent", "plan", "next step"))
        started = time.monotonic()
        writer.start()
        frame = await asyncio.wait_for(stream.__anext__(), timeout=10)
        waited = time.monotonic() - started
        assert "event: plan" in frame and waited < 5
        key = (goal_wakeup.world_key(world.path), gid)
        assert key in goal_wakeup._watchers, "watching while open"
        await stream.aclose()
        assert key not in goal_wakeup._watchers and not sem.locked()
        writer.join()

    asyncio.run(run())
