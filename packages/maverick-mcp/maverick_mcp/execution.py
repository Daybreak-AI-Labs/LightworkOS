"""Owned cooperative MCP execution and thread-free completion waits."""
from __future__ import annotations

import asyncio
import math
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import ContextVar, copy_context

from maverick.killswitch import Halted, bind_local_check


class CompletionSignal:
    """One terminal signal usable by sync callers and async transports.

    Register/check and set share a lock, so completion cannot fall between the
    check and waiter registration. Cancellation removes only that waiter.
    """

    def __init__(self):
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._waiters: dict[asyncio.Future, asyncio.AbstractEventLoop] = {}

    def is_set(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)

    @staticmethod
    def _resolve(future):
        if not future.done():
            future.set_result(None)

    def set(self) -> None:
        with self._lock:
            self._event.set()
            waiters = tuple(self._waiters.items())
        for future, loop in waiters:
            try:
                loop.call_soon_threadsafe(self._resolve, future)
            except RuntimeError:  # A closed client loop no longer owns a wait.
                pass

    async def wait_async(self, timeout: float | None = None) -> bool:
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        with self._lock:
            if self._event.is_set():
                return True
            self._waiters[future] = loop
        try:
            await asyncio.wait_for(future, timeout)
            return True
        except asyncio.TimeoutError:
            return False
        finally:
            with self._lock:
                self._waiters.pop(future, None)


class ExecutionCancelled(Halted):
    def __init__(self):
        super().__init__("MCP execution cancellation requested", "mcp_execution")


class ExecutionHandle:
    def __init__(self, *, deadline: float | None = None):
        self._lock = threading.Lock()
        self.deadline = deadline
        self.cancelled = CompletionSignal()
        self.finished = CompletionSignal()
        self.started = False
        self.acknowledged = False
        self.reason = None

    def cancel(self, reason: str = "request") -> bool:
        with self._lock:
            if self.finished.is_set():
                return False
            if self.reason is None:
                self.reason = reason
            self.cancelled.set()
            return True

    def check(self) -> None:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.cancel("expired")
        if self.cancelled.is_set():
            with self._lock:
                self.acknowledged = True
            raise ExecutionCancelled

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "cancelRequested": self.cancelled.is_set(),
                "cancelAcknowledged": self.acknowledged,
                "executionFinished": self.finished.is_set(),
                "executionStarted": self.started,
                "effectStatus": "unknown" if self.started else "not_started",
            }

    @contextmanager
    def scope(self):
        token = _current.set(self)
        try:
            with bind_local_check(self.check):
                self.check()
                with self._lock:
                    self.started = True
                yield
                self.check()
        finally:
            _current.reset(token)


_current: ContextVar[ExecutionHandle | None] = ContextVar("mcp_execution", default=None)


def current_execution() -> ExecutionHandle | None:
    return _current.get()


def check_execution() -> None:
    handle = current_execution()
    if handle is not None:
        handle.check()


class RequestAdmissionError(ValueError):
    pass


class RequestExecutions:
    """Bounded connection-owned work; cancellation never releases a live slot."""

    def __init__(self, *, workers: int = 8, capacity: int = 128, per_owner: int = 32):
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="mcp-request")
        self._entries: dict[tuple, tuple[ExecutionHandle, Future, str]] = {}
        self._capacity = capacity
        self._per_owner = per_owner
        # One owner may never hold every worker THREAD: a cancelled call keeps
        # its thread until the tool returns, so one owner's blocking calls could
        # otherwise stall every other owner. With 4+ workers, a quarter always
        # remain for others. (Async waits occupy no thread and are not counted.)
        # A serial pool (fewer than 4 workers) queues by design instead.
        self._thread_share = workers - workers // 4 if workers >= 4 else per_owner
        self._threaded: dict[tuple, str] = {}
        self._closed = False

    @staticmethod
    def _key(owner: str, request_id: object) -> tuple:
        if isinstance(request_id, bool) or not isinstance(request_id, (str, int, float, type(None))):
            raise RequestAdmissionError("invalid request id")
        if isinstance(request_id, float) and not math.isfinite(request_id):
            raise RequestAdmissionError("invalid request id")
        if isinstance(request_id, str) and len(request_id) > 256:
            raise RequestAdmissionError("request id exceeds limit")
        return owner, type(request_id).__name__, request_id

    def _admit(self, owner: str, request_id: object, quota_owner: str | None = None,
               handle: ExecutionHandle | None = None, *, threaded: bool = False):
        key = self._key(owner, request_id)
        quota_owner = owner if quota_owner is None else quota_owner
        with self._lock:
            if self._closed:
                raise RequestAdmissionError("request executor is shutting down")
            if key in self._entries:
                raise RequestAdmissionError("request id is already active")
            if len(self._entries) >= self._capacity or sum(entry[2] == quota_owner for entry in self._entries.values()) >= self._per_owner:
                raise RequestAdmissionError("too many active requests")
            if threaded and sum(o == quota_owner for o in self._threaded.values()) >= self._thread_share:
                raise RequestAdmissionError("too many active requests")
            handle, marker = handle or ExecutionHandle(), Future()
            self._entries[key] = handle, marker, quota_owner
            if threaded:
                self._threaded[key] = quota_owner
        return key, handle, marker

    def _finish(self, key, handle, marker, *, result=None, error=None):
        # Marker completion corresponds to actual worker/coroutine exit, never
        # to a cancelled asyncio wrapper or the moment a stop was requested.
        # The id is released before anyone waiting is woken: a reply sent on
        # the marker must never race a client's next request reusing that id.
        with self._lock:
            self._entries.pop(key, None)
            self._threaded.pop(key, None)
        handle.finished.set()
        if error is None:
            marker.set_result(result)
        else:
            marker.set_exception(error)

    def submit(self, owner: str, request_id: object, function, *, quota_owner: str | None = None, handle: ExecutionHandle | None = None):
        key, handle, marker = self._admit(owner, request_id, quota_owner, handle, threaded=True)
        context = copy_context()

        def execute():
            with handle.scope():
                return function()

        try:
            future = self._executor.submit(context.run, execute)
        except BaseException as exc:
            self._finish(key, handle, marker, error=exc)
            raise

        def finished(completed):
            error = completed.exception()
            self._finish(key, handle, marker, result=None if error else completed.result(), error=error)

        future.add_done_callback(finished)
        return handle, marker

    async def run(self, owner: str, request_id: object, function, *, quota_owner: str | None = None, handle: ExecutionHandle | None = None):
        handle, marker = self.submit(owner, request_id, function, quota_owner=quota_owner, handle=handle)
        wrapped = asyncio.wrap_future(marker)
        # The connection can disappear before this real worker reports its
        # outcome. Retain/retrieve that outcome even when no awaiter remains.
        wrapped.add_done_callback(self._consume_async_result)
        try:
            return await asyncio.shield(wrapped)
        except asyncio.CancelledError:
            handle.cancel("disconnect")
            raise

    @staticmethod
    def _consume_async_result(future):
        if not future.cancelled():
            future.exception()

    async def run_async(self, owner: str, request_id: object, function, *, quota_owner: str | None = None, handle: ExecutionHandle | None = None):
        key, handle, marker = self._admit(owner, request_id, quota_owner, handle)
        result, error = None, None

        async def execute():
            with handle.scope():
                return await function()

        worker = asyncio.create_task(execute())
        stopped = asyncio.create_task(handle.cancelled.wait_async())
        try:
            done, _ = await asyncio.wait({worker, stopped}, return_when=asyncio.FIRST_COMPLETED)
            if stopped in done and not worker.done():
                worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)
                handle.check()
            result = await worker
            return result
        except BaseException as exc:
            error = exc
            handle.cancel("disconnect")
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)
            raise
        finally:
            stopped.cancel()
            await asyncio.gather(stopped, return_exceptions=True)
            self._finish(key, handle, marker, result=result, error=error)

    def cancel(self, owner: str, request_id: object) -> bool:
        try:
            key = self._key(owner, request_id)
        except RequestAdmissionError:
            return False
        with self._lock:
            entry = self._entries.get(key)
        return bool(entry and entry[0].cancel())

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [handle.snapshot() for handle, _, _ in self._entries.values()]

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
            handles = [handle for handle, _, _ in self._entries.values()]
        for handle in handles:
            handle.cancel("shutdown")
        self._executor.shutdown(wait=False, cancel_futures=False)
