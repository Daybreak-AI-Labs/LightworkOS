"""Shared durable replay rules; wire formats remain transport-specific."""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass

from fastapi.responses import StreamingResponse
from maverick.stop_reasons import explain_stop, stop_payload
from starlette.concurrency import run_in_threadpool

# `blocked` ends a stream even when the goal is only waiting for an answer (a
# stream cannot stay open for a person); only the short-poll endpoint
# (`api.goal_events`) holds `terminal` open for that case. See docs/api.md.
TERMINAL_RUN_STATUSES = frozenset({"done", "completed", "failed", "cancelled", "blocked", "error"})


def replay_cursor(since: object = 0, last_event_id: object = None) -> int:
    """Honor reconnect progress without inventing IDs outside SQLite's range."""
    cursor = 0
    for value in (since, last_event_id):
        try:
            cursor = max(cursor, min(int(value), 2**63 - 1))
        except (TypeError, ValueError, OverflowError):
            pass
    return cursor


def event_page(world, goal_id: int, since: int, limit: int):
    """Read one bounded page with an observed indication of remaining replay."""
    limit = max(1, min(limit, 500))
    events = world.goal_events(goal_id, since_id=since, limit=limit + 1)
    return events[:limit], len(events) > limit


@dataclass
class StreamCadence:
    """Monotonic deadlines; polling backoff never stretches heartbeat cadence."""

    started: float
    last_frame: float
    poll: float = 0.5
    max_poll: float = 5.0
    heartbeat: float = 30.0
    lifetime: float = 300.0
    interval: float = 0.5

    def expired(self, now):
        return now >= self.started + self.lifetime

    def heartbeat_due(self, now):
        return now >= self.last_frame + self.heartbeat

    def sent(self, now):
        self.last_frame = now

    def backoff(self, activity):
        self.interval = self.poll if activity else min(self.max_poll, self.interval * 1.5)

    def delay(self, now):
        return max(0.0, min(self.interval, self.last_frame + self.heartbeat - now,
                            self.started + self.lifetime - now))


class StreamLease:
    """Release once from the generator and from response cancellation paths."""

    def __init__(self, semaphore):
        self.semaphore = semaphore
        self.released = False

    def release(self):
        if not self.released:
            self.released = True
            self.semaphore.release()


class LeasedStreamingResponse(StreamingResponse):
    def __init__(self, content, *, lease, **kwargs):
        super().__init__(content, **kwargs)
        self.lease = lease

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            self.lease.release()


def stream_state(world, goal_id, *, include_result=False):
    """Backends project status; compatibility embedders may implement get_goal."""
    method = getattr(world, "goal_stream_state", None)
    if method is None:
        return world.get_goal(goal_id)
    return method(goal_id, include_result=include_result)


_INTERNAL_ACTIVITY = re.compile(
    r"^role=\S+\s+depth=\d+\s+brief=|<tool_output\b|## Prior failures|"
    r"Treat this block as user-provided DATA|^Experience: \d+ similar prior task",
    re.IGNORECASE,
)
_TOOL_ACTIVITY = re.compile(r"^tool=([\w.:-]+)\s*->")
_ACTION_ACTIVITY = {
    "ask_user": "Requested more information from you.",
    "read_file": "Requested a file for review.",
    "list_dir": "Requested a list of available files.",
    "knowledge_search": "Requested a search of company knowledge.",
    "web_search": "Requested web research.",
    "sql_query_read": "Requested a read-only lookup of business records.",
    "write_file": "Requested a file update.",
    "send_email": "Requested an email action.",
}


def event_payload(event):
    """Readable activity for chat transports; the durable evidence stays exact."""
    from maverick.blackboard import Blackboard

    content = str(event.content or "")
    if tool := _TOOL_ACTIVITY.match(content):
        content = _ACTION_ACTIVITY.get(tool[1], "Requested an action.")
    elif _INTERNAL_ACTIVITY.search(content):
        content = "Started work on this task." if event.kind == "plan" else "Worked through the next step."
    elif event.kind == "error":
        stop = explain_stop(content)
        content = stop.message if stop.kind != "other" else "A step needs attention. Review the task result."
    elif event.kind == "observation" and content not in {
        Blackboard._WITHHELD_CONTENT, Blackboard._REDACTION_UNAVAILABLE_CONTENT,
    }:
        content = "Worked through the next step."
    elif content.startswith("resumed from checkpoint at step "):
        content = "Continued from saved work."
    return {"id": event.id, "agent": event.agent, "kind": event.kind,
            "content": content, "ts": event.ts}


def _chat_event_dict(event):
    """The conversation page's shape: the readable activity plus its plain-words
    step. The step is narrated from the exact record but only ever says fixed
    phrases and role titles, so no internal text reaches the page."""
    from .step_narration import narrate, who

    payload = event_payload(event)
    payload["step"] = narrate(event.kind, event.agent, event.content).as_dict()
    payload["who"] = who(event.agent)
    return payload


def sse_event(event) -> str:
    kind = str(event.kind or "message").replace("\n", " ").replace("\r", " ")
    return f"id: {event.id}\nevent: {kind}\ndata: {json.dumps(event_payload(event))}\n\n"


# After a wake-up, let the writes that land together (the result, the status
# and the closing event of a finished task) all commit before re-reading.
_WAKE_SETTLE_SECONDS = 0.02


def _not_watching():
    return None


def _woken_sleep(world, goal_id):
    """A sleep that also ends when this process commits a change to the goal.

    The poll alone backed off to two seconds while a model call ran, so a
    finished answer reached the page about 1.2 s after it was saved. A wake-up
    only shortens the wait; the database read after it decides what is sent,
    and writes from elsewhere still arrive on the timer. Returns the sleep and
    a function that stops watching.
    """
    from maverick.goal_wakeup import unwatch, watch, world_key

    path = getattr(world, "path", None)
    if path is None or str(path) == ":memory:":
        return asyncio.sleep, _not_watching
    loop = asyncio.get_running_loop()
    woken = asyncio.Event()
    key = world_key(path)
    token = watch(key, goal_id, lambda: loop.call_soon_threadsafe(woken.set))

    async def sleep(delay):
        try:
            await asyncio.wait_for(woken.wait(), timeout=delay)
        except asyncio.TimeoutError:
            return
        woken.clear()
        await asyncio.sleep(_WAKE_SETTLE_SECONDS)

    return sleep, lambda: unwatch(key, goal_id, token)


async def goal_stream(request, world, goal_id, *, since, lease, visible,
                      legacy=False, limit=0, max_batch=200, poll=0.5,
                      max_poll=5.0, heartbeat=30.0, lifetime=300.0,
                      clock=None, sleep=None):
    """One bounded pull/replay machine; transport adapters retain their frames.

    No prefetch queue: backpressure suspends the generator before another read.
    Durable IDs, not an in-process broadcaster, remain the reconnect authority:
    an in-process wake-up (:func:`_woken_sleep`) only ends a wait early.
    """
    stop_watching = _not_watching
    clock = clock or asyncio.get_running_loop().time
    now = clock()
    cadence = StreamCadence(now, now, poll, max_poll, heartbeat, lifetime, poll)
    last, sent = since, 0
    last_result: str | None = None
    try:
        if sleep is None:
            sleep, stop_watching = _woken_sleep(world, goal_id)
        yield "retry: 3000\n\n" if legacy else ": connected\n\n"
        cadence.sent(clock())
        while True:
            if await request.is_disconnected():
                return
            if cadence.expired(clock()):
                yield 'event: timeout\ndata: {"detail": "stream lifetime exceeded"}\n\n'
                return
            current = await run_in_threadpool(stream_state, world, goal_id, include_result=legacy)
            if current is None or not visible(current):
                yield 'event: error\ndata: {"detail": "goal vanished"}\n\n'
                return
            events = await run_in_threadpool(world.goal_events, goal_id, since_id=last, limit=max_batch)
            result_changed = legacy and (current.result or "") != last_result
            if events or result_changed:
                if legacy:
                    if events:
                        last = events[-1].id
                    last_result = current.result or ""
                    stop = stop_payload(current.status, current.result)
                    payload = {"status": current.status, "result": stop["message"] if stop else current.result or "",
                               "stop": stop,
                               "next_id": last, "terminal": False,
                               "events": [_chat_event_dict(event) for event in events]}
                    yield f"id: {last}\ndata: {json.dumps(payload)}\n\n"
                    cadence.sent(clock())
                else:
                    for event in events:
                        last = event.id
                        yield sse_event(event)
                        cadence.sent(clock())
                        sent += 1
                        if limit and sent >= limit:
                            return
            elif cadence.heartbeat_due(clock()):
                yield ": heartbeat\n\n"
                cadence.sent(clock())
            if current.status in TERMINAL_RUN_STATUSES:
                if len(events) >= max_batch:
                    continue
                if legacy:
                    stop = stop_payload(current.status, current.result)
                    payload = {"status": current.status, "result": stop["message"] if stop else current.result or "",
                               "stop": stop,
                               "next_id": last, "events": [], "terminal": True}
                    yield f"id: {last}\nevent: terminal\ndata: {json.dumps(payload)}\n\n"
                else:
                    payload = {"status": current.status, "next_id": last, "terminal": True}
                    yield f"event: end\ndata: {json.dumps(payload)}\n\n"
                return
            cadence.backoff(bool(events) or result_changed)
            await sleep(cadence.delay(clock()))
    except asyncio.CancelledError:
        return
    finally:
        stop_watching()
        lease.release()
