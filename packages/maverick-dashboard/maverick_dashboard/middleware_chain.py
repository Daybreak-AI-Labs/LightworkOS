"""Run consecutive ``@app.middleware("http")`` functions as one layer.

Each function is a ``BaseHTTPMiddleware``; every layer adds a task group and a
memory stream to each request, about 150 microseconds, and the dashboard
stacks 13 of them in a row (about 2 ms on every page, file and poll). A run of
consecutive function middlewares becomes one ``BaseHTTPMiddleware`` whose
dispatch calls the functions in the same order, with the same cached request
(so a bounded body replays once), the inner functions' response or exception,
and each inner function in its own task with a copy of the caller's context,
so a context variable an inner function sets never reaches an outer one.

Three things differ from separate layers, and none of the merged functions
does them: an outer function receives the inner function's own response
object rather than a streaming copy of it (a plain response has no
``body_iterator``); if it then returns a different response, the inner one's
background task does not run; and a different request passed to
``call_next`` reaches the inner function. A function that does any of these
must stay outside the merged run.
"""
from __future__ import annotations

import asyncio
import functools
from typing import Any

from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware


async def _in_own_task(step: Any, index: int, request: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:  # pragma: no cover - not asyncio: no task to copy into
        return await step(index, request)
    # Like the next layer's own task: a copy of this context, cancelled with it.
    return await asyncio.ensure_future(step(index, request))


def chain(dispatches: list[Any]) -> Any:
    """One dispatch that runs ``dispatches`` outermost first."""
    last = len(dispatches) - 1

    async def dispatch(request: Any, call_next: Any) -> Any:
        async def step(index: int, request: Any) -> Any:
            inner = call_next if index == last else functools.partial(_in_own_task, step, index + 1)
            return await dispatches[index](request, inner)

        return await step(0, request)

    dispatch.chained = tuple(dispatches)  # type: ignore[attr-defined]
    return dispatch


def merge_function_middleware(app: Any) -> int:
    """Merge each run of consecutive function middlewares into one layer.

    Must run after the last ``add_middleware`` and before the first request
    (the stack is built then). Returns how many layers were removed.
    """
    if getattr(app, "middleware_stack", None) is not None:
        return 0
    merged: list[Middleware] = []
    run: list[Middleware] = []

    def flush() -> None:
        if len(run) > 1:
            merged.append(Middleware(BaseHTTPMiddleware, dispatch=chain([m.kwargs["dispatch"] for m in run])))
        else:
            merged.extend(run)
        run.clear()

    for entry in app.user_middleware:  # outermost first
        if entry.cls is BaseHTTPMiddleware and not entry.args and set(entry.kwargs) == {"dispatch"}:
            run.append(entry)
            continue
        flush()
        merged.append(entry)
    flush()
    removed = len(app.user_middleware) - len(merged)
    app.user_middleware[:] = merged
    return removed
