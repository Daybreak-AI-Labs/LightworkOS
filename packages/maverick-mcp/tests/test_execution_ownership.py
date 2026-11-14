"""Owned cancellation, real worker accounting and nonblocking MCP waits."""
from __future__ import annotations

import asyncio
import json
import queue
import sys
import threading
import time
from types import SimpleNamespace

import httpx
import pytest
from maverick import agent_trust, killswitch
from maverick.agent import Agent
from maverick.agent_trust import TrustedAgent
from maverick.budget import Budget
from maverick_mcp import http_transport as ht
from maverick_mcp.execution import (
    CompletionSignal,
    ExecutionCancelled,
    ExecutionHandle,
    RequestAdmissionError,
    RequestExecutions,
    current_execution,
)
from maverick_mcp.server import MCPServer
from maverick_mcp.tasks import TaskError, TaskStore


def ok(text="ok"):
    return {"isError": False, "content": [{"type": "text", "text": text}]}


async def eventually(predicate):
    async def wait():
        while not predicate():
            await asyncio.sleep(0.005)

    await asyncio.wait_for(wait(), 2)


def test_task_cancel_acknowledgment_does_not_free_worker_or_claim_rollback():
    entered, cleanup, release = threading.Event(), threading.Event(), threading.Event()
    proceed = threading.Event()
    effects = []

    def runner(name, args):
        entered.set()
        try:
            while not proceed.wait(0.005):
                killswitch.check()
            killswitch.check()
        except ExecutionCancelled:
            cleanup.set()
            assert release.wait(2)
            raise
        effects.append("must not happen")
        return ok()

    store = TaskStore(runner, max_workers=1, max_tasks=1)
    try:
        task = store.create("tool", {}, {})
        assert entered.wait(1)
        cancelled = store.cancel(task.id)
        assert cancelled["status"] == "cancelled"
        assert cleanup.wait(1)
        metadata = store.get(task.id)["_meta"]["lightwork/execution"]
        assert metadata["cancelAcknowledged"] is True
        assert metadata["executionFinished"] is False
        assert metadata["effectStatus"] == "unknown"
        with pytest.raises(TaskError, match="too many active"):
            store.create("tool", {}, {})
        proceed.set()
        release.set()
        task.future.result(timeout=2)
        assert task.execution.finished.wait(1)
        assert store.get(task.id)["status"] == "cancelled" and effects == []
    finally:
        release.set()
        store.shutdown()


def test_queued_cancel_never_invokes_runner_and_owns_capacity_until_drained():
    release, entered = threading.Event(), threading.Event()
    ran = []

    def runner(name, args):
        ran.append(name)
        entered.set()
        release.wait(2)
        return ok()

    store = TaskStore(runner, max_workers=1, max_tasks=2)
    try:
        first = store.create("first", {}, {})
        assert entered.wait(1)
        queued = store.create("queued", {}, {})
        store.cancel(queued.id)
        with pytest.raises(TaskError, match="too many active"):
            store.create("third", {}, {})
        assert not queued.future.done()
        release.set()
        first.future.result(2)
        queued.future.result(2)
        assert ran == ["first"]
        assert queued.execution.snapshot() == {"cancelRequested": True, "cancelAcknowledged": True,
            "executionFinished": True, "executionStarted": False, "effectStatus": "not_started"}
    finally:
        release.set()
        store.shutdown()


@pytest.mark.parametrize("stop", ["expiry", "shutdown"])
def test_expiry_and_shutdown_reach_owned_cooperative_runner(stop):
    entered = threading.Event()

    def runner(name, args):
        entered.set()
        while True:
            killswitch.check()
            time.sleep(0.005)

    store = TaskStore(runner, max_workers=1)
    task = store.create("tool", {}, {"ttl": 50 if stop == "expiry" else 60_000})
    try:
        assert entered.wait(1)
        if stop == "shutdown":
            store.shutdown()
        task.future.result(2)
        assert task.status == "cancelled" and task.execution.acknowledged
        assert task.execution.finished.wait(1)
        if stop == "shutdown":
            with pytest.raises(TaskError, match="shutting down"):
                store.create("new", {}, {})
    finally:
        store.shutdown()


@pytest.mark.asyncio
async def test_async_result_waiters_use_no_dispatch_threads_and_recheck_authority():
    release = threading.Event()
    store = TaskStore(lambda n, a: (release.wait(2), ok("sensitive"))[1], max_tasks=64, max_workers=1)
    task = store.create("tool", {}, {}, owner="a")
    permitted = True
    waits = [asyncio.create_task(store.result_async(task.id, owner="a", reauthorize=lambda _: permitted)) for _ in range(40)]
    try:
        await eventually(lambda: store._result_waiters == 40)
        assert len(store._executor._threads) == 1
        assert store.get(task.id, owner="a")["status"] == "working"
        with pytest.raises(TaskError, match="not found"):
            await store.result_async(task.id, owner="other")
        waits[0].cancel()
        await asyncio.gather(waits[0], return_exceptions=True)
        assert store._result_waiters == 39
        permitted = False
        release.set()
        results = await asyncio.wait_for(asyncio.gather(*waits[1:], return_exceptions=True), 2)
        assert all(isinstance(r, TaskError) and "not found" in str(r) for r in results)
        assert store._result_waiters == 0
    finally:
        release.set()
        await asyncio.gather(*waits, return_exceptions=True)
        store.shutdown()


@pytest.mark.asyncio
async def test_local_stop_reaches_real_agent_guard_and_copied_thread_but_not_peer():
    handle = ExecutionHandle()
    agent = Agent.__new__(Agent)
    agent.ctx = SimpleNamespace(budget=Budget(max_wall_seconds=5))
    agent._HALT_POLL_SECONDS = 0.01
    entered, provider_closed = asyncio.Event(), asyncio.Event()

    async def provider():
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            provider_closed.set()

    async def owned():
        with handle.scope():
            await agent._await_wall_clock_guarded(provider, in_flight_note="local test provider")

    call = asyncio.create_task(owned())
    await entered.wait()
    killswitch.check()  # Another async request has no owned stop.
    handle.cancel()
    with pytest.raises(ExecutionCancelled):
        await call
    assert provider_closed.is_set() and handle.acknowledged
    killswitch.check()
    copied = ExecutionHandle()
    with pytest.raises(ExecutionCancelled), copied.scope():
        assert await asyncio.to_thread(current_execution) is copied
        copied.cancel()
        await asyncio.to_thread(killswitch.check)
    assert current_execution() is None
    await asyncio.to_thread(killswitch.check)


@pytest.mark.asyncio
async def test_disconnect_keeps_noncooperative_worker_slot_and_no_replay():
    pool = RequestExecutions(workers=1, capacity=1, per_owner=1)
    entered, release = threading.Event(), threading.Event()
    calls = []

    def blocking():
        calls.append("once")
        entered.set()
        release.wait(2)
        return "result"

    messages = asyncio.Queue()
    request = SimpleNamespace(receive=messages.get)
    call = asyncio.create_task(ht._wait_json_dispatch(request, pool.run("owner", 1, blocking)))
    try:
        await eventually(entered.is_set)
        await messages.put({"type": "http.disconnect"})
        with pytest.raises(asyncio.CancelledError):
            await call
        assert pool.snapshot()[0]["cancelRequested"]
        assert not pool.snapshot()[0]["executionFinished"]
        assert not pool.snapshot()[0]["cancelAcknowledged"]
        with pytest.raises(RequestAdmissionError, match="too many active"):
            await pool.run("owner", 2, lambda: None)
        release.set()
        await eventually(lambda: not pool.snapshot())
        assert calls == ["once"]
        assert await pool.run("owner", 3, lambda: (killswitch.check(), "healthy")[1]) == "healthy"
    finally:
        release.set()
        pool.shutdown()


@pytest.mark.asyncio
async def test_completion_signal_handles_cancelled_waiters_without_lost_wakeup():
    signal = CompletionSignal()
    waits = [asyncio.create_task(signal.wait_async(1)) for _ in range(20)]
    await asyncio.sleep(0)
    waits[0].cancel()
    await asyncio.to_thread(signal.set)
    results = await asyncio.gather(*waits, return_exceptions=True)
    assert isinstance(results[0], asyncio.CancelledError)
    assert results[1:] == [True] * 19 and signal._waiters == {}
    assert await signal.wait_async(0.001)


def http_server(monkeypatch, *, tasks=False):
    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "0")
    monkeypatch.setenv("MAVERICK_MCP_HTTP_TASKS", "1" if tasks else "0")
    monkeypatch.setenv("MAVERICK_MCP_RATE_PER_MINUTE", "10000")
    registry = {name: TrustedAgent(id=name, mcp_token=f"{name}-token", max_risk="high") for name in ("one", "other")}
    monkeypatch.setattr(agent_trust, "load_trust_state", lambda: (True, registry))
    server = MCPServer()
    server._shield = None
    server._structured_result = lambda _name: None
    return server, ht.build_app(server)


@pytest.mark.asyncio
async def test_http_request_cancel_is_caller_bound_and_stops_followup_actions(monkeypatch):
    server, app = http_server(monkeypatch)
    entered = threading.Event()
    proceed = threading.Event()
    effects = []

    def run(name, arguments):
        entered.set()
        while not proceed.wait(0.005):
            killswitch.check()
        killswitch.check()
        effects.append("later action")
        return "finished"

    server._dispatch_tool = run
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
        call = asyncio.create_task(client.post("/mcp", headers={"Authorization": "Bearer one-token"}, json={"id": 7, "method": "tools/call", "params": {"name": "maverick_status"}}))
        try:
            await eventually(entered.is_set)
            for token in ("other-token", "one-token"):
                response = await client.post("/mcp", headers={"Authorization": f"Bearer {token}"}, json={"method": "notifications/cancelled", "params": {"requestId": 7}})
                assert response.status_code == 204
                if token == "other-token":
                    assert not server._requests.snapshot()[0]["cancelRequested"]
            response = await asyncio.wait_for(call, 2)
            assert response.json()["error"]["code"] == -32800
            assert effects == []
            await eventually(lambda: not server._requests.snapshot())
            proceed.set()
            healthy = await client.post("/mcp", headers={"Authorization": "Bearer one-token"}, json={"id": 8, "method": "tools/call", "params": {"name": "maverick_status"}})
            assert healthy.json()["result"]["isError"] is False
            assert effects == ["later action"]
        finally:
            server.shutdown()
            await asyncio.gather(call, return_exceptions=True)


class InputPipe:
    def __init__(self):
        self.lines = queue.Queue()

    def send(self, message):
        self.lines.put(json.dumps(message) + "\n")

    def readline(self):
        return self.lines.get(timeout=3)


def test_stdio_reader_handles_ping_and_cancel_during_ordinary_tool(monkeypatch):
    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "0")
    server, pipe, output = MCPServer(), InputPipe(), queue.Queue()
    server._shield = None
    server._send = output.put
    server._structured_result = lambda _name: None
    monkeypatch.setattr(sys, "stdin", pipe)
    entered = threading.Event()

    def run(name, arguments):
        entered.set()
        while True:
            killswitch.check()
            time.sleep(0.005)

    server._dispatch_tool = run
    thread = threading.Thread(target=server.run)
    thread.start()
    try:
        pipe.send({"id": 1, "method": "tools/call", "params": {"name": "maverick_status"}})
        assert entered.wait(1)
        pipe.send({"id": 2, "method": "ping"})
        pipe.send({"method": "notifications/cancelled", "params": {"requestId": 1}})
        replies = [output.get(timeout=2), output.get(timeout=2)]
        assert any(r.get("id") == 2 and r.get("result") == {} for r in replies)
        assert next(r for r in replies if r.get("id") == 1)["error"]["code"] == -32800
    finally:
        pipe.lines.put("")
        thread.join(3)
        server.shutdown()
    assert not thread.is_alive()


def test_stdio_serial_tools_keep_reader_and_queued_cancellation_live(monkeypatch):
    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "0")
    server, pipe, output = MCPServer(), InputPipe(), queue.Queue()
    server._shield = None
    server._send = output.put
    server._structured_result = lambda _name: None
    server.handle_initialize({"capabilities": {"elicitation": {}}})
    monkeypatch.setattr(sys, "stdin", pipe)
    server._dispatch_tool = lambda name, args: json.dumps(server._elicit(args["label"], {"type": "object"}))
    thread = threading.Thread(target=server.run)
    thread.start()
    try:
        for request_id in (1, 2):
            pipe.send({"id": request_id, "method": "tools/call", "params": {"name": "maverick_status", "arguments": {"label": str(request_id)}}})
        request = output.get(timeout=2)
        assert request["method"] == "elicitation/create"
        with pytest.raises(queue.Empty):
            output.get(timeout=0.05)  # Ordinary effects are still serialized.
        pipe.send({"method": "notifications/cancelled", "params": {"requestId": 2}})
        pipe.send({"id": 3, "method": "ping"})
        assert output.get(timeout=2)["id"] == 3
        pipe.send({"id": "elicit-unmatched", "result": {"action": "accept"}})
        pipe.send({"id": request["id"], "result": {"action": "accept", "content": {"answer": "1"}}})
        replies = [output.get(timeout=2), output.get(timeout=2)]
        first = next(r for r in replies if r.get("id") == 1)
        data = json.loads(first["result"]["content"][0]["text"])
        assert data["content"]["answer"] == "1"
        assert next(r for r in replies if r.get("id") == 2)["error"]["code"] == -32800
    finally:
        pipe.lines.put("")
        thread.join(3)
        server.shutdown()
    assert not thread.is_alive()


@pytest.mark.asyncio
async def test_request_quota_survives_session_rotation_and_cancellation():
    pool = RequestExecutions(workers=2, capacity=3, per_owner=1)
    release = threading.Event()
    first = asyncio.create_task(pool.run("session-one", 1, lambda: release.wait(2), quota_owner="principal"))
    try:
        await eventually(lambda: len(pool.snapshot()) == 1)
        pool.cancel("session-one", 1)
        with pytest.raises(RequestAdmissionError, match="too many active"):
            await pool.run("session-two", 2, lambda: None, quota_owner="principal")
        assert await pool.run("unrelated", 1, lambda: "ready", quota_owner="peer") == "ready"
        release.set()
        with pytest.raises(ExecutionCancelled):
            await first
    finally:
        release.set()
        pool.shutdown()


@pytest.mark.asyncio
async def test_connection_cancel_does_not_cancel_detached_task():
    request_release, task_release, started = threading.Event(), threading.Event(), threading.Event()
    created = []

    def runner(name, args):
        started.set()
        while not task_release.wait(0.005):
            killswitch.check()
        return ok("durable")

    store = TaskStore(runner)
    pool = RequestExecutions(workers=1)

    def create():
        created.append(store.create("tool", {}, {}))
        request_release.wait(2)
        return {"task": created[0].create_result}

    request = asyncio.create_task(pool.run("owner", 1, create))
    try:
        await eventually(started.is_set)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        assert created[0].status == "working" and not created[0].execution.cancelled.is_set()
        request_release.set()
        task_release.set()
        assert (await store.result_async(created[0].id))["content"][0]["text"] == "durable"
        assert created[0].status == "completed"
        await eventually(lambda: not pool.snapshot())
    finally:
        request_release.set()
        task_release.set()
        pool.shutdown()
        store.shutdown()


@pytest.mark.asyncio
async def test_http_many_result_waits_leave_get_cancel_and_health_responsive(monkeypatch):
    server, app = http_server(monkeypatch, tasks=True)
    release = threading.Event()
    server._task_runner = lambda name, args, context=None: (release.wait(30), ok())[1]
    headers = {"Authorization": "Bearer one-token"}
    waits = []
    # Generous bounds for loaded CI runners: a call blocked behind the result
    # waits would wait for the 30-second runner, far past any of them.
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
        try:
            created = await client.post("/mcp", headers=headers, json={"id": 1, "method": "tools/call", "params": {"name": "maverick_start", "arguments": {"title": "local test"}, "task": {}}})
            task_id = created.json()["result"]["task"]["taskId"]
            headers["Mcp-Session-Id"] = created.headers["Mcp-Session-Id"]
            waits = [asyncio.create_task(client.post("/mcp", headers=headers, json={"id": i + 10, "method": "tasks/result", "params": {"taskId": task_id}})) for i in range(20)]
            await eventually(lambda: server._task_store()._result_waiters == 20)
            health = await asyncio.wait_for(client.get("/healthz"), 5)
            assert health.status_code == 200
            fetched = await asyncio.wait_for(client.post("/mcp", headers=headers, json={"id": 100, "method": "tasks/get", "params": {"taskId": task_id}}), 5)
            assert fetched.json()["result"]["status"] == "working"
            cancelled = await asyncio.wait_for(client.post("/mcp", headers=headers, json={"id": 101, "method": "tasks/cancel", "params": {"taskId": task_id}}), 5)
            assert cancelled.json()["result"]["status"] == "cancelled"
            results = await asyncio.wait_for(asyncio.gather(*waits), 5)
            assert all(r.json()["result"]["isError"] for r in results)
            assert not server._task_store()._tasks[task_id].future.done()
        finally:
            release.set()
            await asyncio.gather(*waits, return_exceptions=True)
            server.shutdown()


@pytest.mark.asyncio
async def test_ordinary_http_queue_rechecks_rotated_credential_before_dispatch(monkeypatch):
    server, app = http_server(monkeypatch)
    server._requests.shutdown()
    server._requests = RequestExecutions(workers=1)
    _, registry = agent_trust.load_trust_state()
    entered, release = threading.Event(), threading.Event()
    calls = []

    def run(name, arguments):
        calls.append(arguments["label"])
        entered.set()
        release.wait(2)
        return "done"

    server._dispatch_tool = run
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
        def call(request_id):
            return client.post("/mcp", headers={"Authorization": "Bearer one-token"}, json={"id": request_id, "method": "tools/call", "params": {"name": "maverick_status", "arguments": {"label": request_id}}})

        first = asyncio.create_task(call(1))
        await eventually(entered.is_set)
        second = asyncio.create_task(call(2))
        try:
            await eventually(lambda: len(server._requests.snapshot()) == 2)
            registry["one"] = TrustedAgent(id="one", mcp_token="rotated-token", max_risk="high")
            release.set()
            results = await asyncio.wait_for(asyncio.gather(first, second), 2)
            assert results[0].json()["result"]["isError"] is False
            assert "error" in results[1].json()
            assert calls == [1]
        finally:
            release.set()
            await asyncio.gather(first, second, return_exceptions=True)
            server.shutdown()


@pytest.mark.parametrize("error, status", [(asyncio.CancelledError, "cancelled"), (SystemExit, "failed")])
def test_base_exception_cannot_leave_finished_worker_in_working_state(error, status):
    def runner(name, args):
        raise error("private failure detail")

    store = TaskStore(runner, max_tasks=1)
    try:
        task = store.create("tool", {}, {})
        with pytest.raises(error):
            task.future.result(2)
        assert task.status == status
        assert "private failure detail" not in json.dumps(store.get(task.id))
        assert store.result(task.id)["isError"]
        assert task.execution.finished.wait(1)
        assert not store._task_occupies_capacity(task)
    finally:
        store.shutdown()


@pytest.mark.asyncio
async def test_result_wait_limit_releases_slots_after_caller_cancellation():
    release = threading.Event()
    store = TaskStore(lambda n, a: (release.wait(2), ok())[1], max_tasks=2)
    task = store.create("tool", {}, {})
    waits = [asyncio.create_task(store.result_async(task.id)) for _ in range(2)]
    try:
        await eventually(lambda: store._result_waiters == 2)
        with pytest.raises(TaskError, match="too many pending"):
            await store.result_async(task.id)
        waits[0].cancel()
        await asyncio.gather(waits[0], return_exceptions=True)
        assert store._result_waiters == 1
        release.set()
        assert (await store.result_async(task.id))["isError"] is False
        await waits[1]
        assert store._result_waiters == 0
    finally:
        release.set()
        await asyncio.gather(*waits, return_exceptions=True)
        store.shutdown()


@pytest.mark.parametrize("disconnect", [True, False])
@pytest.mark.asyncio
async def test_sse_disconnect_or_completion_has_one_owned_outcome(monkeypatch, disconnect):
    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "0")
    monkeypatch.setenv("MAVERICK_MCP_SSE_HEARTBEAT", "0.01")
    server = MCPServer()
    server._shield = None
    server._structured_result = lambda _: None
    handles = []

    def dispatch(name, args):
        handles.append(current_execution())
        if disconnect:
            while True:
                killswitch.check()
                time.sleep(0.005)
        return "done"

    server._dispatch_tool = dispatch
    stream = ht._sse_stream(server=server, method="tools/call", params={"name": "maverick_status", "_meta": {"progressToken": "p"}}, task_owner=None, subscriptions=set(), request_id=1, should_persist_session=False, sid=None, store_session=lambda *_: None)
    try:
        first = await asyncio.wait_for(anext(stream), 1)
        if disconnect:
            assert "notifications/progress" in first
            await eventually(lambda: len(handles) == 1)
        else:
            while '"result"' not in first:
                first = await asyncio.wait_for(anext(stream), 1)
        await stream.aclose()
        await eventually(lambda: not server._requests.snapshot())
        assert len(handles) == 1 and handles[0].finished.is_set()
        assert handles[0].cancelled.is_set() is disconnect
        assert handles[0].acknowledged is disconnect
    finally:
        await stream.aclose()
        server.shutdown()


def test_stdio_cancel_received_before_async_admission_cannot_execute(monkeypatch):
    from maverick_mcp.stdio_transport import StdioSession

    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "0")
    server = MCPServer()
    output = queue.Queue()
    server._send = output.put
    calls = []
    server._dispatch_tool = lambda *args: calls.append("effect") or "ok"
    session = StdioSession(server)
    entered, release = threading.Event(), threading.Event()

    def block_loop():
        entered.set()
        release.wait(2)

    session.loop.call_soon_threadsafe(block_loop)
    try:
        assert entered.wait(1)
        session.route({"id": 1, "method": "tools/call", "params": {"name": "maverick_status"}})
        session.route({"method": "notifications/cancelled", "params": {"requestId": 1}})
        release.set()
        assert output.get(timeout=2)["error"]["code"] == -32800
        assert calls == []
    finally:
        release.set()
        session.close()
        server.shutdown()


def test_one_owner_cannot_hold_every_worker():
    import asyncio
    import threading

    pool = RequestExecutions()
    release = threading.Event()

    def blocking():
        release.wait(5)
        return "A"

    async def main():
        held = []
        for i in range(64):
            try:
                pool.submit("A:s", i, blocking, quota_owner="A")
                held.append(i)
            except RequestAdmissionError:
                break
        assert 0 < len(held) < 8
        assert await asyncio.wait_for(pool.run("B:s", 1, lambda: "B", quota_owner="B"), 2) == "B"
        release.set()
    try:
        asyncio.run(main())
    finally:
        release.set()


def test_a_finished_request_id_is_free_before_its_result_is_delivered():
    # A reply is sent as soon as the result arrives; the client may then reuse
    # the id at once (JSON-RPC ids only need to be unique while in flight).
    pool = RequestExecutions(workers=1)
    reused, go = [], threading.Event()
    try:
        _handle, marker = pool.submit("owner", 1, lambda: go.wait(5) and "done")

        def reuse(_completed):
            try:
                reused.append(pool.submit("owner", 1, lambda: "again")[1])
            except Exception as exc:  # noqa: BLE001 -- recorded for the assertion
                reused.append(exc)

        marker.add_done_callback(reuse)  # registered while the work still runs
        go.set()
        assert marker.result(timeout=5) == "done"
        deadline = time.monotonic() + 5
        while not reused and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(reused) == 1 and not isinstance(reused[0], Exception), reused
        assert reused[0].result(timeout=5) == "again"
    finally:
        pool.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["reuse", "cancel"])
@pytest.mark.parametrize("initialized", [False, True])
async def test_same_credential_connections_have_independent_request_ids_and_cancellation(monkeypatch, operation, initialized):
    server, app = http_server(monkeypatch)
    entered = threading.Event()
    release = threading.Event()

    def run(name, arguments):
        if arguments.get("wait"):
            entered.set()
            while not release.wait(0.005):
                killswitch.check()
        return "finished"

    server._dispatch_tool = run
    headers = {"Authorization": "Bearer one-token"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 10001)), base_url="http://localhost") as one, \
            httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 10001 if initialized else 10002)), base_url="http://localhost") as two:
        if initialized:
            sessions = []
            for client in (one, two):
                reply = await client.post("/mcp", headers=headers, json={"id": 0, "method": "initialize"})
                sessions.append(reply.headers["Mcp-Session-Id"])
            assert sessions[0] != sessions[1]
        call = asyncio.create_task(one.post("/mcp", headers=headers, json={"id": 7, "method": "tools/call", "params": {"name": "maverick_status", "arguments": {"wait": True}}}))
        try:
            await eventually(entered.is_set)
            if operation == "reuse":
                peer = await two.post("/mcp", headers=headers, json={"id": 7, "method": "tools/call", "params": {"name": "maverick_status"}})
                assert "result" in peer.json()
            await two.post("/mcp", headers=headers, json={"method": "notifications/cancelled", "params": {"requestId": 7}})
            assert not server._requests.snapshot()[0]["cancelRequested"]
            await one.post("/mcp", headers=headers, json={"method": "notifications/cancelled", "params": {"requestId": 7}})
            stopped = await asyncio.wait_for(call, 2)
            assert stopped.json()["error"]["code"] == -32800
        finally:
            release.set()
            await asyncio.gather(call, return_exceptions=True)
            server.shutdown()
