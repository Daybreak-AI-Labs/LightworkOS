"""Single stdin reader with bounded owned tool dispatch and elicitation routing."""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from concurrent.futures import TimeoutError as FutureTimeoutError
from concurrent.futures import wait

from maverick import killswitch

from .execution import ExecutionCancelled, ExecutionHandle, RequestAdmissionError, RequestExecutions
from .protocol import ProtocolError as _ProtocolError
from .tasks import TaskError

log = logging.getLogger(__name__)


def send_stdio_message(message: dict, *, stream, lock) -> None:
    """Write one complete JSON-RPC line without interleaving notifications."""
    line = json.dumps(message) + "\n"
    with lock:
        stream.write(line)
        stream.flush()


class StdioSession:
    def __init__(self, server):
        self.server = server
        self.loop = asyncio.new_event_loop()
        self._lock = threading.Lock()
        self._pending = {}
        self._elicitation: dict[str, tuple[threading.Event, dict]] = {}
        self._closed = False
        self._thread = threading.Thread(target=self._serve, name="mcp-stdio-dispatch", daemon=True)
        self._thread.start()

    def _serve(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()
        self.loop.close()

    def route(self, message: dict) -> bool:
        method = message.get("method")
        request_id = message.get("id")
        if method is None and isinstance(request_id, str):
            with self._lock:
                pending = self._elicitation.get(request_id)
            if pending is not None:
                event, result = pending
                result.update(message)
                event.set()
            return True
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return False
        if method == "notifications/cancelled":
            try:
                key = RequestExecutions._key("stdio", params.get("requestId"))
            except RequestAdmissionError:
                return True
            with self._lock:
                pending = self._pending.get(key)
            if pending is not None:
                pending[0].cancel()
            return True
        if method not in {"tools/call", "tasks/result"}:
            return False
        # Task creation only admits a detached job; it does not run the tool on
        # this reader. Keeping this short acknowledgment synchronous avoids a
        # needless ownership hop and preserves request ordering for task IDs.
        if method == "tools/call" and isinstance(params.get("task"), dict) and self.server._tasks_enabled:
            return False
        try:
            key = RequestExecutions._key("stdio", request_id)
        except RequestAdmissionError as exc:
            self.server._send_error(None, -32602, str(exc))
            return True
        with self._lock:
            if self._closed or len(self._pending) >= 64 or key in self._pending:
                if "id" in message:
                    self.server._send_error(request_id, -32602, "stdio request capacity or duplicate active id")
                return True
            handle = ExecutionHandle()
            future = asyncio.run_coroutine_threadsafe(self._dispatch(message, handle), self.loop)
            self._pending[key] = handle, future
        future.add_done_callback(lambda completed: self._done(key, completed))
        return True

    def _done(self, key, future):
        with self._lock:
            self._pending.pop(key, None)
        # Retrieve cancellation/errors so transport teardown owns all outcomes.
        if not future.cancelled():
            future.exception()

    async def _dispatch(self, message, handle):
        request_id = message.get("id")
        params = message.get("params") or {}
        with self.server.resource_update_scope(set(self.server._subscriptions)):
            try:
                if message["method"] == "tasks/result":
                    result = await self.server._requests.run_async(
                        "stdio", request_id, lambda: self.server.handle_tasks_result_async(params),
                        handle=handle,
                    )
                else:
                    result = await self.server._requests.run(
                        "stdio", request_id, lambda: self.server.handle_tools_call(params),
                        handle=handle,
                    )
            except (TaskError, _ProtocolError) as exc:
                if "id" in message:
                    self.server._send_error(request_id, exc.code, exc.message)
            except ExecutionCancelled:
                if "id" in message:
                    self.server._send_error(request_id, -32800, "request cancelled; prior effects may be unknown")
            except RequestAdmissionError as exc:
                if "id" in message:
                    self.server._send_error(request_id, -32602, str(exc))
            except Exception as exc:
                if "id" in message:
                    self.server._send_error(request_id, -32603, f"internal error: {type(exc).__name__}")
            else:
                if "id" in message:
                    self.server._send_result(request_id, result)
                self.server._flush_resource_updates()

    def elicit(self, message: dict, timeout: float) -> dict | None:
        request_id = message["id"]
        event, reply = threading.Event(), {}
        with self._lock:
            if self._closed:
                return None
            self._elicitation[request_id] = event, reply
        try:
            self.server._send(message)
            deadline = time.monotonic() + timeout
            while not event.wait(max(0.0, min(0.05, deadline - time.monotonic()))):
                killswitch.check()
                if time.monotonic() >= deadline:
                    return None
            killswitch.check()
            if "error" in reply:
                return None
            result = reply.get("result")
            return result if isinstance(result, dict) else None
        finally:
            with self._lock:
                self._elicitation.pop(request_id, None)

    def close(self):
        with self._lock:
            self._closed = True
            pending = tuple(future for _, future in self._pending.values())
            elicitations = tuple(self._elicitation.values())
        # Let already-completed responses flush, then treat EOF as disconnect.
        if pending:
            _, remaining = wait(pending, timeout=0.1)
            for future in remaining:
                future.cancel()
        for event, _ in elicitations:
            event.set()

        async def drain():
            current = asyncio.current_task()
            tasks = [t for t in asyncio.all_tasks() if t is not current]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        drained = asyncio.run_coroutine_threadsafe(drain(), self.loop)
        drained.add_done_callback(lambda _: self.loop.call_soon_threadsafe(self.loop.stop))
        try:
            drained.result(timeout=2)
        except FutureTimeoutError:
            # An uninterruptible synchronous authority check may still own the
            # loop. It stops only once its pending coroutine cleanup completes.
            log.warning("stdio dispatch cleanup remains in progress")
        self._thread.join(timeout=2)


def dispatch_stdio_message(server, method, request_id, params, is_notification) -> None:
    """Route a parsed stdio message using the shared protocol method table."""
    from .protocol import METHOD_HANDLERS

    handler_name = METHOD_HANDLERS.get(method) if isinstance(method, str) else None
    if handler_name is not None:
        server._send_result(request_id, getattr(server, handler_name)(params))
        if method == "tools/call":
            # Result first, then any resources/updated notifications.
            server._flush_resource_updates()
    elif method == "notifications/initialized":
        pass
    elif method == "ping":
        if not is_notification:
            server._send_result(request_id, {})
    else:
        if not is_notification:
            server._send_error(request_id, -32601, f"method not found: {method}")


def handle_stdio_line(server, line: str, *, no_id, logger) -> None:
    """Parse + dispatch one input line, translating handler exceptions into
    JSON-RPC error responses. Behavior identical to the prior loop body."""
    try:
        msg = json.loads(line)
    except json.JSONDecodeError as e:
        logger.warning("bad JSON: %s", e)
        return
    # A top-level JSON-RPC message must be an object. A batch (list) or a
    # scalar would make `msg.get(...)` raise AttributeError and tear down
    # the stdio loop. Reject with -32600 (Invalid Request); batches are
    # acknowledged with a null-id error rather than crashing.
    if not isinstance(msg, dict):
        server._send_error(None, -32600, "Invalid Request: expected a JSON-RPC object")
        return
    if server._stdio_session is not None and server._stdio_session.route(msg):
        return
    method = msg.get("method")
    # Distinguish a MISSING id (notification, no reply) from an explicit
    # `"id": null` (a request still owed a response). `no_id` is the
    # missing sentinel; only a missing id marks a notification.
    request_id = msg.get("id", no_id)
    is_notification = request_id is no_id
    if is_notification:
        request_id = None
    params = msg.get("params", {}) or {}
    # A client can send `params` as a non-object (list/string/number).
    # Handlers call `params.get(...)`, which would raise AttributeError
    # -- caught below as a scrubbed -32603 "internal error". Coerce to
    # {} so a malformed-params call yields the correct -32602 invalid-
    # params response from the handler instead.
    if not isinstance(params, dict):
        params = {}
    try:
        server._dispatch_stdio_message(method, request_id, params, is_notification)
    except TaskError as e:
        if not is_notification:
            server._send_error(request_id, e.code, e.message)
    except _ProtocolError as e:
        if not is_notification:
            server._send_error(request_id, e.code, e.message)
    except Exception as e:
        logger.exception("handler error")  # full traceback stays server-side
        if not is_notification:
            # Do NOT ship the traceback to the client: frames/locals/args
            # can carry secrets (DSNs, tokens, credentialed URLs). Send a
            # scrubbed one-line message; the server log keeps the detail.
            try:
                from maverick.secrets import scrub
                detail = scrub(f"{type(e).__name__}: {e}")
            except Exception:  # pragma: no cover
                detail = type(e).__name__
            server._send_error(request_id, -32603, f"internal error: {detail}")


def serve_stdio(server, *, stdin, protocol_version: str, logger) -> None:
    """Own the stdin loop and session lifecycle for one MCP client."""
    if server._requests.snapshot():
        raise RuntimeError("cannot restart stdio while prior request execution is active")
    server._requests.shutdown()
    # One ordinary tool runs at a time while the reader remains available for
    # cancellation, task controls, and elicitation replies.
    server._requests = RequestExecutions(workers=1)
    logger.info("Lightwork MCP server starting (protocol %s)", protocol_version)
    server._stdio = True
    server._tasks_enabled = True
    server._stdio_session = StdioSession(server)
    try:
        while True:
            line = stdin.readline()
            if not line:
                break
            line = line.strip()
            if line:
                server._handle_stdio_line(line)
    finally:
        server._stdio_session.close()
        server._stdio_session = None
        server._stdio = False
