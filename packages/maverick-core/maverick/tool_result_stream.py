"""Bounded collection before screening; progress contains no producer content.

The quota bounds retained UTF-8 result bytes, not arbitrary allocations made by
third-party tool code before yielding. Synchronous workers retain ownership
until they physically exit, even when their awaiting coroutine is cancelled.
"""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import inspect
import threading
from collections.abc import Callable

from .connector_attempts import CONTROL_ERRORS

_STOP_ERRORS = CONTROL_ERRORS + (asyncio.CancelledError, KeyboardInterrupt, SystemExit)
MAX_RESULT_BYTES = 16 * 1024 * 1024
COPY_CHARS = 64 * 1024
MAX_WORKERS = 32
# A named tenant may hold at most this many workers, so a tenant whose tools
# hang (a worker is only returned when its thread exits) cannot refuse every
# other tenant's tools. The default single-tenant deployment keeps all of them.
MAX_WORKERS_PER_TENANT = 24
_workers: set = set()
_worker_tenant: dict = {}
_workers_lock = threading.Lock()
_cleanup_tasks: set = set()
_invocations: set = set()
_execution_output = contextvars.ContextVar("complete_tool_execution_output", default=False)


class ToolOutputLimit(ValueError):
    """The result cannot be represented completely within its byte quota."""

    tool_execution_unknown = True


class ToolOutputIncomplete(RuntimeError):
    """A producer failed during result collection or cleanup after dispatch."""

    tool_execution_unknown = True


class ToolOutputUncertain(str):
    """Delivery failed after dispatch; the effect must not be blindly repeated."""

    tool_execution_unknown = True


class ToolWorkerCapacity(RuntimeError):
    """No worker was admitted; the tool function has not been called."""


@contextlib.contextmanager
def execution_output_scope():
    """Trusted programmatic execution consumes full screened values, not previews."""
    token = _execution_output.set(True)
    try:
        yield
    finally:
        _execution_output.reset(token)


def needs_complete_output() -> bool:
    return _execution_output.get()


def result_bytes(text: str, *, limit: int = MAX_RESULT_BYTES) -> int:
    if len(text) > limit:
        raise ToolOutputLimit("complete tool output exceeds the 16 MiB byte quota")
    size = 0
    for start in range(0, len(text), COPY_CHARS):
        size += len(text[start:start + COPY_CHARS].encode("utf-8"))
        if size > limit:
            raise ToolOutputLimit("complete tool output exceeds the 16 MiB byte quota")
    return size


class ResultSink:
    def __init__(self, progress: Callable[[int], None] | None = None):
        self._data = bytearray()
        self._progress = progress
        self._last_progress = -COPY_CHARS

    @property
    def retained_bytes(self) -> int:
        return len(self._data)

    def append(self, chunk) -> None:
        text = chunk if isinstance(chunk, str) else str(chunk)
        if len(text) > MAX_RESULT_BYTES - len(self._data):
            raise ToolOutputLimit("complete tool output exceeds the 16 MiB byte quota")
        for start in range(0, len(text), COPY_CHARS):
            data = text[start:start + COPY_CHARS].encode("utf-8")
            if len(self._data) + len(data) > MAX_RESULT_BYTES:
                raise ToolOutputLimit("complete tool output exceeds the 16 MiB byte quota")
            self._data.extend(data)
        if self._progress is not None and len(self._data) - self._last_progress >= COPY_CHARS:
            self._last_progress = len(self._data)
            try:
                self._progress(len(self._data))
            except Exception:
                pass

    def finish(self) -> str:
        text = self._data.decode("utf-8")
        self.clear()
        return text

    def clear(self) -> None:
        self._data.clear()


def pending_tool_workers() -> int:
    """Actual queued/running synchronous invocations, not cancelled awaiters."""
    with _workers_lock:
        return len(_workers)


def pending_tool_invocations() -> int:
    """Owned async work, including cancellation-resistant collection/cleanup."""
    with _workers_lock:
        return len(_invocations) + len(_cleanup_tasks)


async def _owned_thread(fn, stop: threading.Event):
    started = threading.Event()
    handle = object()
    try:
        from .paths import current_tenant_id
        tenant = current_tenant_id() or ""
    except Exception:  # noqa: BLE001 -- unknown tenant: count it on its own
        tenant = "?"
    with _workers_lock:
        if len(_workers) >= MAX_WORKERS:
            raise ToolWorkerCapacity("tool worker capacity exhausted; no tool was dispatched")
        if tenant and sum(1 for t in _worker_tenant.values() if t == tenant) >= MAX_WORKERS_PER_TENANT:
            raise ToolWorkerCapacity("this tenant's tool worker share is exhausted; no tool was dispatched")
        _workers.add(handle)
        _worker_tenant[handle] = tenant

    def release():
        _workers.discard(handle)
        _worker_tenant.pop(handle, None)

    def execute():
        with _workers_lock:
            if stop.is_set():
                release()
                return None
            started.set()
        try:
            return fn()
        finally:
            with _workers_lock:
                release()

    task = asyncio.create_task(asyncio.to_thread(execute))

    def observe(completed):
        if completed.cancelled():
            stop.set()
        try:
            completed.exception()
        except BaseException:
            pass
        with _workers_lock:
            if not started.is_set():
                release()

    task.add_done_callback(observe)
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError as exc:
        stop.set()
        exc.tool_execution_unknown = started.is_set() and not task.done()
        raise


def _cleanup_failed(error, stop_error):
    if stop_error is not None:
        stop_error.tool_execution_unknown = True
        raise stop_error from error
    if isinstance(error, _STOP_ERRORS):
        error.tool_execution_unknown = True
        raise error
    raise ToolOutputIncomplete("tool result cleanup failed") from error


async def _close_async(iterator, stop_error=None) -> None:
    close = getattr(iterator, "aclose", None)
    if close is None:
        return
    task = asyncio.create_task(close())
    with _workers_lock:
        _cleanup_tasks.add(task)

    def observe(completed):
        with _workers_lock:
            _cleanup_tasks.discard(completed)
        try:
            completed.exception()
        except BaseException:
            pass

    task.add_done_callback(observe)
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=1.0)
    except BaseException as exc:
        _cleanup_failed(exc, stop_error)


def _drain_sync(out, stop, sink):
    if inspect.isgenerator(out) or (hasattr(out, "__next__") and not isinstance(out, str)):
        stop_error = None
        try:
            for chunk in out:
                if stop.is_set():
                    return None
                sink.append(chunk)
            return sink.finish()
        except _STOP_ERRORS as exc:
            stop_error = exc
            raise
        except Exception as exc:
            if isinstance(exc, ToolOutputLimit):
                raise
            raise ToolOutputIncomplete("tool result stream failed") from exc
        finally:
            close = getattr(out, "close", None)
            if close is not None:
                try:
                    close()
                except BaseException as exc:
                    _cleanup_failed(exc, stop_error)
    return out


async def _collect_tool(fn, args: dict, progress: Callable[[int], None] | None = None):
    """Preserve complete values and connector metadata under a fixed collection cap."""
    stop = threading.Event()
    sink = ResultSink(progress)

    try:
        if inspect.iscoroutinefunction(fn):
            out = await fn(args)
        elif inspect.isasyncgenfunction(fn):
            out = fn(args)
        else:
            out = await _owned_thread(lambda: _drain_sync(fn(args), stop, sink), stop)
        if inspect.isawaitable(out):
            out = await out
        if inspect.isasyncgen(out) or hasattr(out, "__anext__"):
            stop_error = None
            try:
                async for chunk in out:
                    sink.append(chunk)
                    await asyncio.sleep(0)  # even a producer with no awaits yields to cancellation
                return sink.finish()
            except _STOP_ERRORS as exc:
                stop_error = exc
                raise
            except Exception as exc:
                if isinstance(exc, ToolOutputLimit):
                    raise
                raise ToolOutputIncomplete("tool result stream failed") from exc
            finally:
                await _close_async(out, stop_error)
        if inspect.isgenerator(out) or (hasattr(out, "__next__") and not isinstance(out, str)):
            out = await _owned_thread(lambda: _drain_sync(out, stop, sink), stop)
        from .tool_results import ToolOutcome

        if isinstance(out, ToolOutcome):
            out = out.as_text()
        out = "" if out is None else out if isinstance(out, str) else str(out)
        result_bytes(out)
        return out  # do not strip ConnectorResult's retry metadata
    except asyncio.CancelledError as exc:
        stop.set()
        if not hasattr(exc, "tool_execution_unknown"):
            exc.tool_execution_unknown = True
        raise
    finally:
        # A still-running worker owns its sink until it observes cancellation.
        if not stop.is_set():
            sink.clear()


async def execute_tool(fn, args: dict, progress: Callable[[int], None] | None = None):
    """Bound caller cancellation while retaining ownership of unfinished work."""
    with _workers_lock:
        if len(_invocations) + len(_cleanup_tasks) >= MAX_WORKERS:
            raise ToolWorkerCapacity("tool invocation capacity exhausted; no tool was dispatched")
        task = asyncio.create_task(_collect_tool(fn, args, progress))
        _invocations.add(task)

    def observe(completed):
        with _workers_lock:
            _invocations.discard(completed)
        try:
            completed.exception()
        except BaseException:
            pass

    task.add_done_callback(observe)
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError as exc:
        task.cancel()
        # wait_for would inject another cancellation and can still wait forever
        # for a resistant producer. The retained task remains its actual owner.
        await asyncio.wait({task}, timeout=1.0)
        exc.tool_execution_unknown = True
        raise
