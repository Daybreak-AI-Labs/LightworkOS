"""Let a task started from a chat form wait, briefly, for its page.

After Send, the browser follows the redirect to ``/chat/goal/<id>`` while the
run builds its agent: about 200 ms of pure-Python work that, under one
interpreter lock, made that page take about 560 ms instead of 120 ms. The run
now starts once the page has been served, or after :data:`WAIT_SECONDS` if it
never is (another tab, a script, a page that failed).

Timing only: a run never depends on a page for anything but when it starts,
so a page served for another task with the same number only starts this one
sooner.
"""
from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Awaitable, Callable

WAIT_SECONDS = 0.5
_FORGET_AFTER_SECONDS = 60.0

_lock = threading.Lock()
_pending: dict[int, dict] = {}


def expect(goal_id: int) -> None:
    """Before redirecting to the task's page: its run will wait for it."""
    now = time.monotonic()
    with _lock:
        for stale in [gid for gid, entry in _pending.items()
                      if now - entry["since"] > _FORGET_AFTER_SECONDS]:
            del _pending[stale]
        _pending[int(goal_id)] = {"since": now, "served": False, "wake": None}


def served(goal_id: int) -> None:
    """The task's page has been built (or refused): its run may start."""
    with _lock:
        entry = _pending.get(int(goal_id))
        if entry is None:
            return
        entry["served"] = True
        wake = entry["wake"]
    if wake is not None:
        try:
            wake()
        except RuntimeError:  # the waiting loop has closed
            pass


async def wait(goal_id: int, timeout: float | None = None) -> None:
    """Return once the page was served, or after ``timeout`` (default
    :data:`WAIT_SECONDS`)."""
    loop = asyncio.get_running_loop()
    woken = asyncio.Event()
    with _lock:
        entry = _pending.get(int(goal_id))
        if entry is None or entry["served"]:
            _pending.pop(int(goal_id), None)
            return
        entry["wake"] = lambda: loop.call_soon_threadsafe(woken.set)
    try:
        await asyncio.wait_for(woken.wait(), WAIT_SECONDS if timeout is None else timeout)
    except asyncio.TimeoutError:
        pass
    finally:
        with _lock:
            _pending.pop(int(goal_id), None)


def after_page(run: Callable[..., Awaitable]) -> Callable[..., Awaitable]:
    """``run``, started once the task's page was served (see :func:`wait`)."""
    async def start(goal_id, *args, **kwargs):
        await wait(goal_id)
        return await run(goal_id, *args, **kwargs)
    return start
