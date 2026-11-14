"""MCP Tasks (spec 2025-11-25, experimental): async, pollable tool execution.

A task-augmented ``tools/call`` returns a ``CreateTaskResult`` immediately and
runs the tool on a background worker; the requestor polls ``tasks/get`` and
retrieves the result via ``tasks/result`` once terminal. This lets a long
``maverick_start`` run without wedging the single stdio loop — the client can
poll, cancel, or call other tools while the swarm works.

Scope of this module: the basic lifecycle (``working`` → ``completed`` /
``failed`` / ``cancelled``, plus ``get`` / ``result`` / ``list`` / ``cancel``).
The optional ``input_required`` status (task-driven elicitation) and
``notifications/tasks/status`` push are deferred — requestors poll, which the
spec requires them to support regardless.

The store is transport/server-agnostic: it's handed a ``runner`` that turns a
``(tool_name, arguments)`` pair into a ``CallToolResult`` dict, so it unit-tests
without a real server or LLM. ``server.py`` supplies a runner that executes the
tool on a fresh ``MCPServer`` instance (isolated per-call state; no stdio).
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
import secrets
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone

from .execution import CompletionSignal, ExecutionCancelled, ExecutionHandle

log = logging.getLogger(__name__)

TASK_TERMINAL = frozenset({"completed", "failed", "cancelled"})
RELATED_TASK_META = "io.modelcontextprotocol/related-task"

_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603

# Runner: (tool_name, arguments) -> CallToolResult dict (isError + content[/...]).
Runner = Callable[[str, dict], dict]
ContextRunner = Callable[[str, dict, object], dict]
TaskAuthorizer = Callable[[str], bool]


class TaskError(Exception):
    """A JSON-RPC protocol error from a task operation. ``server.py`` maps this
    onto the same wire error its ``_ProtocolError`` produces."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env_int(name: str, default: int, *, lo: int, hi: int, key: str = "") -> int:
    """``name`` from the environment, else ``[mcp] <key>``, else ``default``;
    read when the task manager starts."""
    from .settings import mcp_setting

    raw = mcp_setting(key) if key else os.environ.get(name)
    try:
        v = int(raw if raw is not None else default)
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))


def _first_text(result: dict) -> str:
    for block in result.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "text":
            return str(block.get("text", ""))
    return ""


class McpTask:
    """In-memory record of one task-augmented request's execution state."""

    def __init__(
        self,
        *,
        ttl_ms: int,
        poll_interval_ms: int,
        owner: str | None = None,
        tool_name: str = "",
        quota_owner: str | None = None,
    ):
        # No auth context on stdio (single client owns the pipe), so per the
        # spec's security guidance the id is cryptographically random with
        # ample entropy rather than guessable/sequential.
        self.id = secrets.token_hex(16)
        self.owner = owner
        self.tool_name = tool_name
        # Access ownership is session-bound; quota ownership is caller-bound.
        # Keep them distinct so re-minting a session cannot bypass a principal's
        # active-task ceiling.
        self.quota_owner = owner if quota_owner is None else quota_owner
        self.status = "working"
        self.status_message = "The operation is now in progress."
        self.created_at = _now_iso()
        self.updated_at = self.created_at
        self._created_epoch = time.time()
        self.ttl_ms = ttl_ms
        self.poll_interval_ms = poll_interval_ms
        self.result: dict | None = None
        self.future: Future | None = None
        self.cancel_requested = False
        # Set when the task reaches a terminal status; tasks/result blocks on it.
        self.done = CompletionSignal()
        self.execution = ExecutionHandle(deadline=time.monotonic() + ttl_ms / 1000.0)
        # Frozen "working" snapshot for the CreateTaskResult. Captured here,
        # before the worker is submitted, so the acceptance ack always reports
        # the spec-mandated initial `working` status even if a fast tool has
        # already finished by the time the response is serialized.
        self.create_result = self.to_dict()

    def set_status(self, status: str, message: str | None = None) -> None:
        self.status = status
        if message is not None:
            self.status_message = message
        self.updated_at = _now_iso()
        if status in TASK_TERMINAL:
            self.done.set()

    def is_expired(self, now_epoch: float) -> bool:
        return (
            self.ttl_ms is not None
            and (now_epoch - self._created_epoch) * 1000.0 > self.ttl_ms
        )

    def to_dict(self) -> dict:
        d: dict = {
            "taskId": self.id,
            "status": self.status,
            "createdAt": self.created_at,
            "lastUpdatedAt": self.updated_at,
            "ttl": self.ttl_ms,
            "pollInterval": self.poll_interval_ms,
        }
        if self.status_message:
            d["statusMessage"] = self.status_message
        d["_meta"] = {"lightwork/execution": self.execution.snapshot()}
        return d


class TaskStore:
    """Registry + background executor for MCP tasks.

    Thread-safety: a single lock guards the registry and per-task mutations.
    Workers only mutate their task record (never stdout), so the server's main
    loop stays the sole writer of the transport."""

    def __init__(
        self,
        runner: Runner,
        *,
        context_runner: ContextRunner | None = None,
        max_workers: int | None = None,
        max_tasks: int | None = None,
        max_tasks_per_owner: int | None = None,
        default_ttl_ms: int | None = None,
        max_ttl_ms: int | None = None,
        poll_interval_ms: int | None = None,
        result_block_ms: int | None = None,
        page_size: int = 100,
        on_status_change: Callable[[McpTask], None] | None = None,
    ):
        self._runner = runner
        self._context_runner = context_runner
        # Optional: invoked with the task each time it changes status, so the
        # server can push notifications/tasks/status. Fired outside the lock.
        self._on_status_change = on_status_change
        self._max_tasks = max_tasks if max_tasks is not None else _env_int(
            "MAVERICK_MCP_MAX_TASKS", 256, lo=1, hi=100_000, key="max_tasks")
        # Per-caller sub-cap (HTTP multi-client mode only). The global cap above
        # is shared, and _make_room only evicts TERMINAL tasks, so without this
        # one principal could fill all 256 slots with active tasks and block
        # task creation for every other client. The transport supplies a stable
        # principal scope, distinct from the task's session-bound access owner,
        # so session rotation cannot reset this ceiling. Bounded by the global
        # cap; ignored for stdio (quota_owner=None, single client).
        self._max_tasks_per_owner = (
            max_tasks_per_owner if max_tasks_per_owner is not None else _env_int(
                "MAVERICK_MCP_MAX_TASKS_PER_OWNER",
                min(32, self._max_tasks), lo=1, hi=self._max_tasks, key="max_tasks_per_owner")
        )
        self._default_ttl_ms = default_ttl_ms if default_ttl_ms is not None else _env_int(
            "MAVERICK_MCP_TASK_TTL_MS", 3_600_000, lo=1_000, hi=604_800_000, key="task_ttl_ms")
        self._max_ttl_ms = max_ttl_ms if max_ttl_ms is not None else _env_int(
            "MAVERICK_MCP_TASK_MAX_TTL_MS", 86_400_000, lo=1_000, hi=604_800_000, key="task_max_ttl_ms")
        self._poll_ms = poll_interval_ms if poll_interval_ms is not None else _env_int(
            "MAVERICK_MCP_TASK_POLL_MS", 1_000, lo=50, hi=3_600_000, key="task_poll_ms")
        # Upper bound on how long a single ``tasks/result`` call blocks a worker
        # thread, INDEPENDENT of the task's ttl (see result()). Defaults to 60s.
        self._result_block_ms = result_block_ms if result_block_ms is not None else _env_int(
            "MAVERICK_MCP_TASK_RESULT_BLOCK_MS", 60_000, lo=1_000, hi=600_000, key="task_result_block_ms")
        self._page_size = max(1, page_size)
        workers = max_workers if max_workers is not None else _env_int(
            "MAVERICK_MCP_TASK_WORKERS", 4, lo=1, hi=64, key="task_workers")
        self._executor = ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="mcp-task")
        self._tasks: dict[str, McpTask] = {}
        self._lock = threading.Lock()
        self._closed = False
        self._result_waiters = 0

    # ---- lifecycle ------------------------------------------------------

    def create(
        self,
        name: str,
        arguments: dict,
        task_param: dict,
        *,
        owner: str | None = None,
        quota_owner: str | None = None,
        context: object | None = None,
    ) -> McpTask:
        """Register a task (status working), kick off the worker, return it."""
        self._purge_expired()
        task = McpTask(
            ttl_ms=self._resolve_ttl(task_param),
            poll_interval_ms=self._poll_ms,
            owner=owner,
            tool_name=name,
            quota_owner=quota_owner,
        )
        with self._lock:
            if self._closed:
                raise TaskError(_INVALID_PARAMS, "task store is shutting down")
            self._reject_if_owner_over_quota_locked(task.quota_owner)
            self._make_room_for_task_locked()
            self._tasks[task.id] = task
            # Assign the future under the SAME lock that inserts the task: a
            # concurrent cancel()/_purge_expired() must never observe a freshly
            # inserted task with `future is None` and evict a starting worker.
            task.future = self._executor.submit(
                self._run, task, name, arguments, context)
            task.future.add_done_callback(lambda _future: task.execution.finished.set())
        return task

    def _resolve_ttl(self, task_param: dict) -> int:
        raw = (task_param or {}).get("ttl")
        if isinstance(raw, bool):
            raise TaskError(_INVALID_PARAMS, "ttl must not be a boolean")
        try:
            ttl = int(raw)
        except (TypeError, ValueError, OverflowError):
            ttl = self._default_ttl_ms
        if ttl <= 0:
            ttl = self._default_ttl_ms
        return min(ttl, self._max_ttl_ms)  # receivers MAY override the request

    def _run(
        self,
        task: McpTask,
        name: str,
        arguments: dict,
        context: object | None,
    ) -> None:
        try:
            with task.execution.scope():
                self._run_owned(task, name, arguments, context)
        except ExecutionCancelled:
            changed = False
            with self._lock:
                if task.status not in TASK_TERMINAL:
                    self._cancel_task_locked(task, "The task execution stopped after cancellation or expiry.")
                    changed = True
            if changed:
                self._notify(task)
        except BaseException as exc:
            changed = False
            with self._lock:
                if task.status not in TASK_TERMINAL:
                    if isinstance(exc, asyncio.CancelledError):
                        self._cancel_task_locked(task, "The owned runner was cancelled.")
                    else:
                        task.result = {"isError": True, "content": [{"type": "text", "text": f"task failed: {type(exc).__name__}"}]}
                        task.set_status("failed", f"task failed: {type(exc).__name__}")
                    changed = True
            if changed:
                self._notify(task)
            raise

    def _run_owned(self, task, name, arguments, context) -> None:
        try:
            if context is not None:
                if self._context_runner is None:
                    raise RuntimeError("task execution context has no authorized runner")
                result = self._context_runner(name, arguments, context)
            else:
                result = self._runner(name, arguments)
            task.execution.check()
        except ExecutionCancelled:
            raise
        except Exception as e:  # noqa: BLE001 -- a runner crash must fail the task, not the pool
            log.error("mcp task %s (%s) failed: %s", task.id, name, type(e).__name__)
            changed = False
            with self._lock:
                if task.status not in TASK_TERMINAL:
                    task.result = {
                        "isError": True,
                        "content": [{"type": "text",
                                     "text": f"task failed: {type(e).__name__}"}],
                    }
                    task.set_status("failed", f"task failed: {type(e).__name__}")
                    changed = True
            if changed:
                self._notify(task)
            return
        changed = False
        with self._lock:
            if not (task.cancel_requested or task.status in TASK_TERMINAL):
                task.result = result
                if result.get("isError"):
                    task.set_status("failed", _first_text(result)[:500] or "tool reported an error")
                else:
                    task.set_status("completed", "The operation completed.")
                changed = True
            # else: cancelled while running -- keep cancelled, drop the result.
        if changed:
            self._notify(task)

    # ---- JSON-RPC task methods -----------------------------------------

    def get(
        self,
        task_id: str,
        *,
        owner: str | None = None,
        authorize: TaskAuthorizer | None = None,
    ) -> dict:
        return self._require(task_id, owner=owner, authorize=authorize).to_dict()

    def result(
        self,
        task_id: str,
        *,
        owner: str | None = None,
        authorize: TaskAuthorizer | None = None,
        reauthorize: TaskAuthorizer | None = None,
    ) -> dict:
        task = self._require(task_id, owner=owner, authorize=authorize)
        # Synchronous embedding compatibility. Both transports use result_async
        # so result waits do not occupy dispatch workers. Either API bounds a
        # single wait independently of the task TTL and rechecks authority.
        wait_s = max(1.0, min((task.ttl_ms or 0) / 1000.0 + 5.0,
                              self._result_block_ms / 1000.0))
        task.done.wait(timeout=wait_s)
        return self._result_response(task, reauthorize or authorize)

    async def result_async(
        self, task_id: str, *, owner: str | None = None,
        authorize: TaskAuthorizer | None = None,
        reauthorize: TaskAuthorizer | None = None,
    ) -> dict:
        task = self._require(task_id, owner=owner, authorize=authorize)
        with self._lock:
            if self._result_waiters >= self._max_tasks:
                raise TaskError(_INVALID_PARAMS, "too many pending task result waits")
            self._result_waiters += 1
        try:
            wait_s = max(0.001, min((task.ttl_ms or 0) / 1000.0 + 5.0, self._result_block_ms / 1000.0))
            await task.done.wait_async(wait_s)
            return self._result_response(task, reauthorize or authorize)
        finally:
            with self._lock:
                self._result_waiters -= 1

    def _result_response(self, task: McpTask, final_authorizer: TaskAuthorizer | None) -> dict:
        # Re-check after the potentially long wait: an operator revocation or
        # capability narrowing that lands while result() blocks must prevent
        # the now-sensitive result from crossing the boundary.
        if final_authorizer is not None and not final_authorizer(task.tool_name):
            raise TaskError(_INVALID_PARAMS, "task not found")
        with self._lock:
            if task.status not in TASK_TERMINAL:
                raise TaskError(_INTERNAL_ERROR, "timed out waiting for task result")
            res = task.result
        if res is None:  # cancelled (or odd) -> there is no underlying result
            res = {"isError": True,
                   "content": [{"type": "text", "text": f"task {task.status}"}]}
        out = dict(res)
        meta = dict(out.get("_meta") or {})
        meta[RELATED_TASK_META] = {"taskId": task.id}
        meta["lightwork/execution"] = task.execution.snapshot()
        out["_meta"] = meta
        return out

    def cancel(
        self,
        task_id: str,
        *,
        owner: str | None = None,
        authorize: TaskAuthorizer | None = None,
    ) -> dict:
        self._purge_expired()
        # A hostile client can send a non-string taskId (list/dict); coerce it to
        # "" so the lookup yields a clean -32602 instead of an unhashable-key
        # TypeError (mirrors a2a_tasks._owned).
        key = task_id if isinstance(task_id, str) else ""
        with self._lock:
            task = self._tasks.get(key)
            if (
                task is None
                or not self._owner_matches(task, owner)
                or (authorize is not None and not authorize(task.tool_name))
            ):
                raise TaskError(_INVALID_PARAMS, "task not found")
            if task.status in TASK_TERMINAL:
                raise TaskError(
                    _INVALID_PARAMS,
                    f"cannot cancel task in terminal status {task.status!r}")
            # Request cooperative stop; retain queued/running capacity until
            # the real future exits, and expose acknowledgment separately.
            self._cancel_task_locked(task, "The task was cancelled by request.")
            snapshot = task.to_dict()
        self._notify(task)
        return snapshot

    def list(
        self,
        cursor: str | None,
        *,
        owner: str | None = None,
        authorize: TaskAuthorizer | None = None,
    ) -> dict:
        self._purge_expired()
        start = self._decode_cursor(cursor)
        with self._lock:
            items = [
                task for task in self._tasks.values()
                if self._owner_matches(task, owner)
            ]
        if authorize is not None:
            items = [task for task in items if authorize(task.tool_name)]
        if start > len(items):
            raise TaskError(_INVALID_PARAMS, "invalid cursor")
        chunk = items[start:start + self._page_size]
        out: dict = {"tasks": [t.to_dict() for t in chunk]}
        if start + self._page_size < len(items):
            out["nextCursor"] = base64.urlsafe_b64encode(
                str(start + self._page_size).encode()).decode()
        return out

    # ---- helpers --------------------------------------------------------

    def _require(
        self,
        task_id: str,
        *,
        owner: str | None = None,
        authorize: TaskAuthorizer | None = None,
    ) -> McpTask:
        self._purge_expired()
        # Coerce a non-string taskId (hostile list/dict) to "" so the lookup
        # raises a clean -32602 rather than an unhashable-key TypeError.
        key = task_id if isinstance(task_id, str) else ""
        with self._lock:
            task = self._tasks.get(key)
        if (
            task is None
            or not self._owner_matches(task, owner)
            or (authorize is not None and not authorize(task.tool_name))
        ):
            raise TaskError(_INVALID_PARAMS, "task not found")
        return task

    @staticmethod
    def _owner_matches(task: McpTask, owner: str | None) -> bool:
        # owner=None is the stdio/single-client mode: preserve existing behavior.
        # HTTP passes a per-client session owner to isolate task records while
        # returning the same "task not found" error for absent and foreign ids.
        return owner is None or task.owner == owner

    def _decode_cursor(self, cursor: str | None) -> int:
        if not cursor:
            return 0
        try:
            start = int(base64.urlsafe_b64decode(cursor.encode()).decode())
        except Exception:  # noqa: BLE001 -- opaque token; any garbage is invalid
            raise TaskError(_INVALID_PARAMS, "invalid cursor") from None
        if start < 0:
            raise TaskError(_INVALID_PARAMS, "invalid cursor")
        return start

    def _reject_if_owner_over_quota_locked(self, quota_owner: str | None) -> None:
        # quota_owner=None is stdio/single-client mode: the global cap governs,
        # with no per-caller quota. In HTTP mode, count this caller's records
        # that still occupy the shared worker/queue capacity. That includes
        # non-terminal tasks and cancelled terminal tasks whose Future has not
        # drained yet; otherwise session rotation plus cancel could bypass the
        # caller cap while filling the global cap with non-evictable records.
        if quota_owner is None:
            return
        active = sum(
            1 for t in self._tasks.values()
            if t.quota_owner == quota_owner and self._task_occupies_capacity(t)
        )
        if active >= self._max_tasks_per_owner:
            raise TaskError(
                _INVALID_PARAMS, "too many active tasks for this caller")

    @staticmethod
    def _task_occupies_capacity(task: McpTask) -> bool:
        if task.status not in TASK_TERMINAL:
            return True
        return task.future is not None and not task.future.done()

    def _make_room_for_task_locked(self) -> None:
        # Completed/failed/cancelled records are retained only for polling; drop
        # the oldest terminal snapshots first before rejecting new work. A
        # cancelled task may still occupy the executor queue, so keep it counted
        # until the worker has drained it and the future is done. Never evict
        # active records: losing those task ids would make their queued or
        # running executions unmanageable and defeat the configured task cap.
        while len(self._tasks) >= self._max_tasks:
            for tid, task in self._tasks.items():
                if not self._task_occupies_capacity(task):
                    self._tasks.pop(tid, None)
                    break
            else:
                raise TaskError(_INVALID_PARAMS, "too many active tasks")

    def _cancel_task_locked(self, task: McpTask, message: str) -> None:
        task.cancel_requested = True
        task.execution.cancel()
        # Do not call Future.cancel() here: ThreadPoolExecutor leaves cancelled
        # work items in its internal queue until a worker drains them. Keeping
        # the future pending makes the task continue counting toward
        # _max_tasks, so repeated cancel/expire cycles cannot grow that queue
        # without bound. Running tasks stop at owned cooperative boundaries;
        # noncooperative results are discarded without claiming rollback.
        task.set_status("cancelled", message)

    def _purge_expired(self) -> None:
        now = time.time()
        with self._lock:
            expired = [tid for tid, t in self._tasks.items() if t.is_expired(now)]
            for tid in expired:
                task = self._tasks.get(tid)
                if task is None:
                    continue
                if task.status not in TASK_TERMINAL:
                    self._cancel_task_locked(task, "The task expired.")
                    continue
                if not self._task_occupies_capacity(task):
                    self._tasks.pop(tid, None)

    def _notify(self, task: McpTask) -> None:
        cb = self._on_status_change
        if cb is None:
            return
        try:
            cb(task)
        except Exception:  # noqa: BLE001 -- a notify failure must not break the task
            log.warning("mcp task %s status-notify failed", task.id, exc_info=True)

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
            for task in self._tasks.values():
                if task.status not in TASK_TERMINAL:
                    self._cancel_task_locked(task, "The task store is shutting down.")
        # Retain queued futures until workers drain them. Their owned handles
        # acknowledge cancellation before invoking the runner.
        self._executor.shutdown(wait=False, cancel_futures=False)
