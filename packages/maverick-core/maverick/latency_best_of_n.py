"""Latency-aware best-of-N: race N attempts, take the first success, cancel rest.

Best-of-N runs several attempts and keeps the best; the *latency-aware* variant
returns as soon as the first attempt **succeeds** and cancels the slower ones, so
you don't pay for compute you'll discard. An optional ``budget_ms`` caps the
wall-clock wait. A fast *failure* doesn't win — the race keeps draining until an
attempt succeeds, the budget elapses, or every attempt has failed. Pure asyncio;
unit-tested with fake coroutines.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from .best_of_n import AllAttemptsFailed  # re-export: single shared definition


async def race_first_success(
    factories: list[Callable[[], Awaitable[Any]]],
    *,
    budget_ms: float | None = None,
) -> Any:
    """Run ``factories`` concurrently; return the first successful result.

    Cancels the remaining tasks once one succeeds. Raises ``asyncio.TimeoutError``
    if ``budget_ms`` elapses with no success, or ``AllAttemptsFailed`` if every
    attempt raised first. ``factories`` is a list of zero-arg callables returning
    awaitables (so each attempt is started here, not before).
    """
    if not factories:
        raise ValueError("race_first_success needs at least one factory")
    tasks = [asyncio.ensure_future(f()) for f in factories]
    timeout = None if budget_ms is None else max(0.0, budget_ms / 1000.0)
    deadline = None if timeout is None else asyncio.get_running_loop().time() + timeout
    errors: list[BaseException] = []
    pending = set(tasks)
    try:
        while pending:
            remaining = None
            if deadline is not None:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise asyncio.TimeoutError(
                        f"no attempt succeeded within {budget_ms}ms")
            done, pending = await asyncio.wait(
                pending, timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED)
            if not done:  # timed out this round
                raise asyncio.TimeoutError(
                    f"no attempt succeeded within {budget_ms}ms")
            for task in done:
                exc = task.exception()
                if exc is None:
                    return task.result()  # first success wins
                errors.append(exc)
        raise AllAttemptsFailed(
            f"all {len(tasks)} attempts failed; last: {errors[-1]!r}"
        ) from (errors[-1] if errors else None)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        # Let cancellations settle without surfacing CancelledError.
        await asyncio.gather(*tasks, return_exceptions=True)


__all__ = ["race_first_success", "AllAttemptsFailed"]
