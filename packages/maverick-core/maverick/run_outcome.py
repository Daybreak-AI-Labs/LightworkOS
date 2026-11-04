"""Typed execution control outcomes; display text never grants replay authority."""
from __future__ import annotations

import asyncio
import sys
import weakref


class GoalCancelled(asyncio.CancelledError):
    """The goal owner requested cancellation of this owned execution."""


class GoalAdmissionRefused(str):
    """String-compatible blocked status issued before orchestration starts.

    This certificate concerns this invocation only, not prior attempts of an
    existing goal. The flow binding may use it because it just created the
    child goal. Persisting/displaying the string must not preserve replay
    authority: a reconstructed ordinary ``"blocked"`` is not this type.
    """

    def __new__(cls, goal_id: int, *, stop_kind: str, detail: str):
        value = super().__new__(cls, "blocked")
        value.goal_id = goal_id
        value.stop_kind = stop_kind
        value.detail = detail
        return value


# Python 3.10 only: the cancellation each owned task stopped with (see task_stop).
_TASK_STOPS: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def owned_task(awaitable) -> asyncio.Task:
    """Run ``awaitable`` as a task whose own cancellation :func:`task_stop` can recover."""
    async def run():
        try:
            return await awaitable
        except asyncio.CancelledError as stop:
            if sys.version_info < (3, 11):
                # No local names the task: the stop's traceback must not keep
                # its weak key alive.
                _TASK_STOPS[asyncio.current_task()] = stop
            raise

    return asyncio.ensure_future(run())


def task_stop(task: asyncio.Future, error: BaseException) -> BaseException:
    """The exception ``task`` itself stopped with, given what awaiting it raised.

    A task that raises a ``CancelledError`` (or a subclass such as
    :class:`GoalCancelled`) ends cancelled. Python 3.11+ re-raises that very
    exception to its awaiter; Python 3.10 raises a fresh bare ``CancelledError``,
    dropping the original's type and its ``tool_execution_unknown`` /
    ``usage_status`` markers at the task boundary. For a task started with
    :func:`owned_task` the original is recovered on 3.10; otherwise (and on
    3.11+) ``error`` is returned unchanged.
    """
    if type(error) is asyncio.CancelledError and task.done() and task.cancelled():
        return _TASK_STOPS.get(task, error)
    return error


def cancellation_message(error: BaseException) -> str:
    if getattr(error, "tool_execution_unknown", False):
        return (
            "Cancelled. An in-flight tool may have committed an external effect; "
            "review its outcome before retrying the work."
        )
    return "Cancelled by the goal owner." if isinstance(error, GoalCancelled) else "cancelled"
