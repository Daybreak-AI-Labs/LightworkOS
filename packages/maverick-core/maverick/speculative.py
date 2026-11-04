"""Speculative / overlapped execution primitive.

The agent loop has several places where independent work runs back-to-back
on the event loop even though it could overlap: the verifier call vs. the
tail of generation, post-FINAL bookkeeping vs. skill distillation, a
best-of-N attempt's evaluation vs. the next attempt's generation.

``Speculation`` is the small, reusable building block for all of them:
start a coroutine eagerly (it begins running on the loop right away), then
either ``await result()`` for its value later, or ``cancel()`` it if it
turned out not to be needed (the "speculative" case — you kicked off work
before you were sure you'd use it).

Design goals:
  * Zero behavior change unless a caller opts in — this module adds a
    capability, it doesn't alter any existing path on import.
  * Best-effort friendly: ``run_independent`` fans out fire-and-forget
    side effects and never lets one failure abort the others, matching the
    kernel's "a bad donation must never affect the goal result" contract.
  * Future-proof: the eventual streaming speculative verifier does
    ``spec = speculate(verify_final(...))`` the instant a FINAL marker is
    seen mid-stream, keeps generating, then ``await spec.result()`` —
    hiding the verifier's latency behind the generation tail.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable
from typing import TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")


class Speculation:
    """A coroutine started eagerly, awaited or cancelled later.

    Construct via :func:`speculate`. The wrapped coroutine is scheduled as
    a task immediately, so it makes progress while the caller does other
    work. ``result()`` awaits and caches the value (and re-raises any
    exception the task raised). ``cancel()`` is a no-op once the task has
    finished, so it's always safe to call.
    """

    def __init__(self, coro: Awaitable[T], *, name: str | None = None):
        self._task: asyncio.Task = asyncio.ensure_future(coro)
        if name:
            try:
                self._task.set_name(name)
            except Exception:  # pragma: no cover -- set_name is 3.8+, best-effort
                pass

    @property
    def done(self) -> bool:
        return self._task.done()

    async def result(self) -> T:
        """Await the speculated coroutine and return its value.

        Re-raises whatever the task raised (including CancelledError if it
        was cancelled). Idempotent: awaiting a finished task returns the
        cached result.
        """
        return await self._task

    async def cancel(self) -> None:
        """Cancel the task if it hasn't finished; swallow the cancellation.

        Safe to call multiple times and after completion. Use when the
        speculation turned out to be unnecessary.
        """
        if self._task.done():
            return
        self._task.cancel()
        try:
            await self._task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001 -- discard
            pass


def speculate(coro: Awaitable[T], *, name: str | None = None) -> Speculation:
    """Start ``coro`` running now; return a handle to await or cancel it."""
    return Speculation(coro, name=name)


async def run_independent(
    *coros: Awaitable[object],
    swallow_errors: bool = True,
) -> list[object]:
    """Run independent coroutines concurrently and wait for all of them.

    For fire-and-forget side effects that don't depend on each other (e.g.
    a trajectory-donation write and a conversation-turn write). With
    ``swallow_errors=True`` (the default) one failure never aborts the
    others — exceptions are logged and returned in place of a result, so
    the caller's happy path is unperturbed. Empty input returns ``[]``.
    """
    if not coros:
        return []
    results = await asyncio.gather(*coros, return_exceptions=True)
    if swallow_errors:
        for r in results:
            if isinstance(r, Exception):
                log.debug("independent task failed (swallowed): %s", r)
        return list(results)
    for r in results:
        if isinstance(r, Exception):
            raise r
    return list(results)


__all__ = ["Speculation", "speculate", "run_independent"]
