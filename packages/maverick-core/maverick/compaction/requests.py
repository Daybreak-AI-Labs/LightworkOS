"""Drive shared compaction algorithms with synchronous or native async I/O.

Only ordinary provider errors are sent back to a strategy's fallback. Budget,
accounting, halt and cancellation stop the operation without a second request.
No synchronous provider call is dispatched to a detached worker thread.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..budget import BudgetExceeded, UsageAccountingError
from ..killswitch import Halted
from ..killswitch import check as check_halt

STOP_ERRORS = (BudgetExceeded, UsageAccountingError, Halted)


@dataclass(frozen=True)
class CompletionRequest:
    llm: object
    kwargs: dict


def request(llm, **kwargs) -> CompletionRequest:
    return CompletionRequest(llm, kwargs)


def _check_request(pending):
    check_halt()
    check_budget = getattr(pending.kwargs.get("budget"), "check", None)
    if callable(check_budget):
        check_budget()


def run_sync(steps):
    """Run one algorithm; retain the existing synchronous public interface."""
    response = None
    error = None
    try:
        while True:
            try:
                pending = steps.throw(error) if error else steps.send(response)
            except StopIteration as done:
                return done.value
            error = None
            try:
                _check_request(pending)
                response = pending.llm.complete(**pending.kwargs)
            except STOP_ERRORS:
                raise
            except Exception as exc:
                error = exc
    finally:
        steps.close()


async def run_async(steps):
    """Await native provider I/O; sync-only seams take deterministic fallback."""
    response = None
    error = None
    try:
        while True:
            try:
                pending = steps.throw(error) if error else steps.send(response)
            except StopIteration as done:
                return done.value
            error = None
            try:
                _check_request(pending)
                complete = getattr(pending.llm, "complete_async", None)
                if not callable(complete):
                    raise TypeError("compaction provider requires complete_async")
                response = await complete(**pending.kwargs)
            except STOP_ERRORS:
                raise
            except Exception as exc:
                error = exc
    finally:
        steps.close()
