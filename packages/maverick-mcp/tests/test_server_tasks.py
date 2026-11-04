"""MCP Tasks (spec 2025-11-25): async, pollable tool execution.

A task-augmented tools/call returns a CreateTaskResult immediately and runs the
tool on a background worker; the client polls tasks/get and fetches the result
via tasks/result once terminal. These tests cover the TaskStore lifecycle with a
controllable fake runner (no swarm/LLM), and the server wiring: capability
advertisement (stdio-gated), tool-level taskSupport, the CreateTaskResult path,
and a full run()-loop integration.
"""
from __future__ import annotations

import io
import json
import sys
import threading
import time

import pytest
from maverick_mcp.server import TOOLS, MCPServer, _ProtocolError
from maverick_mcp.tasks import RELATED_TASK_META, McpTask, TaskError, TaskStore


def _ok(text: str) -> dict:
    return {"isError": False, "content": [{"type": "text", "text": text}]}


# ---- TaskStore lifecycle ----------------------------------------------------

def test_create_runs_and_completes_with_related_task_meta():
    release = threading.Event()

    def runner(name, args):
        release.wait(timeout=5)
        return _ok(f"done:{name}:{args.get('title')}")

    store = TaskStore(runner, max_workers=2)
    try:
        task = store.create("maverick_start", {"title": "x"}, {"ttl": 60000})
        assert task.status == "working"
        assert store.get(task.id)["status"] == "working"
        release.set()
        res = store.result(task.id)  # blocks until terminal
        assert res["content"][0]["text"] == "done:maverick_start:x"
        assert res["_meta"][RELATED_TASK_META] == {"taskId": task.id}
        got = store.get(task.id)
        assert got["status"] == "completed"
        assert got["ttl"] == 60000 and got["pollInterval"] > 0
    finally:
        release.set()
        store.shutdown()


def test_per_owner_task_quota_isolates_sessions():
    """One HTTP session can't monopolize the shared global task cap: its ACTIVE
    tasks are bounded by a per-owner sub-cap, while other sessions and the stdio
    (owner=None) path are unaffected. Without this, 256 active tasks from one
    session block task creation for every other client."""
    release = threading.Event()

    def runner(name, args):
        release.wait(timeout=5)
        return _ok("done")

    store = TaskStore(runner, max_workers=4, max_tasks=100, max_tasks_per_owner=2)
    try:
        # Session A fills its per-owner quota with 2 active tasks.
        a1 = store.create("maverick_start", {}, {}, owner="A")
        a2 = store.create("maverick_start", {}, {}, owner="A")
        assert a1.status == "working" and a2.status == "working"
        # A's 3rd active task is rejected by the per-owner quota, even though the
        # global cap (100) is nowhere near full.
        with pytest.raises(TaskError, match="too many active tasks for this caller"):
            store.create("maverick_start", {}, {}, owner="A")
        # A different session B is unaffected by A's saturation.
        assert store.create("maverick_start", {}, {}, owner="B").status == "working"
        # stdio single-client (owner=None) is not subject to the per-owner cap.
        for _ in range(5):
            store.create("maverick_start", {}, {}, owner=None)
    finally:
        release.set()
        store.shutdown()


def test_per_owner_quota_counts_cancelled_tasks_until_future_drains():
    """Cancelled queued/running tasks still occupy global capacity, so they
    must also count toward the per-owner quota until their futures drain."""
    release = threading.Event()

    def runner(name, args):
        release.wait(timeout=5)
        return _ok("done")

    store = TaskStore(runner, max_workers=1, max_tasks=3, max_tasks_per_owner=1)
    try:
        attacker = store.create("maverick_start", {}, {"ttl": 60000}, owner="attacker")
        store.cancel(attacker.id, owner="attacker")

        with pytest.raises(TaskError, match="too many active tasks for this caller"):
            store.create("maverick_start", {}, {"ttl": 60000}, owner="attacker")

        victim = store.create("maverick_start", {}, {"ttl": 60000}, owner="victim")
        assert victim.status == "working"
    finally:
        release.set()
        store.shutdown()


def test_tool_iserror_marks_task_failed():
    store = TaskStore(lambda n, a: {"isError": True,
                                    "content": [{"type": "text", "text": "boom"}]})
    try:
        task = store.create("maverick_start", {}, {})
        res = store.result(task.id)
        assert res["isError"] is True
        assert store.get(task.id)["status"] == "failed"
    finally:
        store.shutdown()


def test_runner_exception_marks_task_failed():
    def runner(name, args):
        raise RuntimeError("kaboom")

    store = TaskStore(runner)
    try:
        task = store.create("maverick_start", {}, {})
        res = store.result(task.id)
        assert res["isError"] is True
        assert store.get(task.id)["status"] == "failed"
        assert "RuntimeError" in store.get(task.id)["statusMessage"]
    finally:
        store.shutdown()


def test_result_call_block_is_bounded_independent_of_ttl():
    """A single tasks/result call must not block a worker thread
    for the task's whole ttl (up to 24h). result() runs on the HTTP dispatch
    pool, so an unbounded wait lets a few large-ttl tasks pin every thread and
    freeze the server. The per-call block is capped (result_block_ms); on timeout
    it raises so the client re-polls -- the task itself keeps running."""
    release = threading.Event()

    def runner(name, args):
        release.wait(timeout=10)  # never released during the assertion
        return _ok("late")

    # Large ttl (60s) but a tiny per-call block ceiling (200ms).
    store = TaskStore(runner, max_workers=2, result_block_ms=200)
    try:
        task = store.create("maverick_start", {}, {"ttl": 60000})
        t0 = time.monotonic()
        with pytest.raises(TaskError):
            store.result(task.id)  # must time out fast, not wait ~60s
        elapsed = time.monotonic() - t0
        assert elapsed < 5.0, f"result() blocked {elapsed:.1f}s -- ttl not bounded"
        # The task is still working (not cancelled/failed) -- only the call ended.
        assert store.get(task.id)["status"] == "working"
    finally:
        release.set()
        store.shutdown()


def test_cancel_transitions_and_rejects_double_cancel():
    release = threading.Event()
    store = TaskStore(lambda n, a: (release.wait(timeout=5), _ok("late"))[1])
    try:
        task = store.create("maverick_start", {}, {"ttl": 60000})
        cancelled = store.cancel(task.id)
        assert cancelled["status"] == "cancelled"
        # tasks/result on a cancelled task: no underlying result.
        res = store.result(task.id)
        assert res["isError"] is True
        # Cancelling an already-terminal task is -32602.
        with pytest.raises(TaskError) as ei:
            store.cancel(task.id)
        assert ei.value.code == -32602
    finally:
        release.set()
        store.shutdown()


def test_cancel_while_running_keeps_cancelled_and_drops_result():
    release = threading.Event()
    store = TaskStore(lambda n, a: (release.wait(timeout=5), _ok("late"))[1])
    try:
        task = store.create("maverick_start", {}, {"ttl": 60000})
        store.cancel(task.id)
        release.set()  # worker finishes after the cancel
        # Give the worker a beat; status must stay cancelled, result discarded.
        import time
        for _ in range(200):
            if store.get(task.id)["status"] == "cancelled":
                break
            time.sleep(0.01)
        assert store.get(task.id)["status"] == "cancelled"
    finally:
        release.set()
        store.shutdown()


def test_active_task_cap_rejects_unbounded_submissions():
    release = threading.Event()
    started = 0
    started_lock = threading.Lock()

    def runner(name, args):
        nonlocal started
        with started_lock:
            started += 1
        release.wait(timeout=5)
        return _ok("done")

    store = TaskStore(runner, max_workers=1, max_tasks=2)
    try:
        first = store.create("maverick_start", {}, {"ttl": 60000})
        second = store.create("maverick_start", {}, {"ttl": 60000})
        for _ in range(200):
            with started_lock:
                if started:
                    break
            time.sleep(0.01)

        with pytest.raises(TaskError) as ei:
            store.create("maverick_start", {}, {"ttl": 60000})
        assert ei.value.code == -32602
        assert "too many active tasks" in ei.value.message

        store.cancel(second.id)
        with pytest.raises(TaskError):
            store.create("maverick_start", {}, {"ttl": 60000})
        with started_lock:
            assert started == 1

        release.set()
        store.result(first.id)
        for _ in range(200):
            if second.future is not None and second.future.done():
                break
            time.sleep(0.01)

        third = store.create("maverick_start", {}, {"ttl": 60000})
        assert store.get(third.id)["status"] == "working"
    finally:
        release.set()
        store.shutdown()


def test_terminal_tasks_are_pruned_when_cap_is_full():
    store = TaskStore(lambda n, a: _ok("done"), max_tasks=1)
    try:
        first = store.create("maverick_start", {}, {"ttl": 60000})
        store.result(first.id)
        second = store.create("maverick_start", {}, {"ttl": 60000})
        assert second.id != first.id
        assert [t["taskId"] for t in store.list(None)["tasks"]] == [second.id]
    finally:
        store.shutdown()


def test_get_and_result_unknown_task_raise_invalid_params():
    store = TaskStore(lambda n, a: _ok("x"))
    try:
        for fn in (store.get, store.result, store.cancel):
            with pytest.raises(TaskError) as ei:
                fn("does-not-exist")
            assert ei.value.code == -32602
    finally:
        store.shutdown()


def test_non_string_task_id_raises_invalid_params_not_typeerror():
    """A hostile client can send a truthy non-string taskId (list/dict). It must
    resolve to a clean -32602 'task not found', not blow up dict.get() with an
    unhashable-key TypeError that escapes as a scrubbed -32603 internal error."""
    store = TaskStore(lambda n, a: _ok("x"))
    try:
        for fn in (store.get, store.result, store.cancel):
            for bad in ({"evil": 1}, [1, 2], {"a": {"b": 1}}):
                with pytest.raises(TaskError) as ei:
                    fn(bad)
                assert ei.value.code == -32602
    finally:
        store.shutdown()


def test_list_paginates_with_opaque_cursor():
    store = TaskStore(lambda n, a: _ok("x"), page_size=2)
    try:
        ids = [store.create("maverick_start", {}, {"ttl": 60000}).id for _ in range(5)]
        page1 = store.list(None)
        assert len(page1["tasks"]) == 2 and "nextCursor" in page1
        page2 = store.list(page1["nextCursor"])
        assert len(page2["tasks"]) == 2 and "nextCursor" in page2
        page3 = store.list(page2["nextCursor"])
        assert len(page3["tasks"]) == 1 and "nextCursor" not in page3
        seen = [t["taskId"] for p in (page1, page2, page3) for t in p["tasks"]]
        assert seen == ids  # insertion order, no dupes/gaps
    finally:
        store.shutdown()


def test_task_store_owner_isolates_http_callers():
    store = TaskStore(lambda n, a: _ok(str(a.get("title", "x"))))
    try:
        alice = store.create(
            "maverick_start", {"title": "alice-secret"}, {"ttl": 60000}, owner="alice")
        bob = store.create(
            "maverick_start", {"title": "bob-secret"}, {"ttl": 60000}, owner="bob")

        assert [t["taskId"] for t in store.list(None, owner="alice")["tasks"]] == [alice.id]
        assert [t["taskId"] for t in store.list(None, owner="bob")["tasks"]] == [bob.id]

        with pytest.raises(TaskError) as ei:
            store.result(alice.id, owner="bob")
        assert ei.value.code == -32602

        assert "alice-secret" in store.result(alice.id, owner="alice")["content"][0]["text"]
    finally:
        store.shutdown()


def test_list_invalid_cursor_raises():
    store = TaskStore(lambda n, a: _ok("x"))
    try:
        with pytest.raises(TaskError) as ei:
            store.list("not-a-valid-cursor!!!")
        assert ei.value.code == -32602
    finally:
        store.shutdown()


def test_expired_task_is_purged():
    from concurrent.futures import wait as _future_wait
    store = TaskStore(lambda n, a: _ok("x"))
    try:
        # A comfortable ttl so result() reliably reaches a terminal state -- a
        # 1ms ttl races the purge inside _require and can vanish before it
        # finishes on a slow runner.
        task = store.create("maverick_start", {}, {"ttl": 60000})
        store.result(task.id)  # block until it finishes
        # result() returns when the terminal-status event fires, which can be a
        # hair before the worker Future is marked done(); an un-done Future still
        # "occupies capacity", so the purge would keep the task. Wait for the
        # Future to settle, then rewind the creation epoch past the ttl so it is
        # deterministically expired on the next access, on any runner.
        if task.future is not None:
            _future_wait([task.future])
        task._created_epoch -= 3600
        with pytest.raises(TaskError) as ei:
            store.get(task.id)  # purged on access
        assert ei.value.code == -32602
    finally:
        store.shutdown()


# ---- server wiring ----------------------------------------------------------

def test_initialize_advertises_tasks_when_enabled():
    # Tasks are advertised when the transport enabled them. stdio's run() sets
    # _tasks_enabled; here we set it directly to simulate that.
    s = MCPServer()
    s._stdio = True
    s._tasks_enabled = True
    caps = s.handle_initialize({})["capabilities"]
    assert caps["tasks"]["requests"]["tools"]["call"] == {}
    assert caps["tasks"]["list"] == {} and caps["tasks"]["cancel"] == {}
    # A transport with tasks disabled (the default, e.g. HTTP without
    # MAVERICK_MCP_HTTP_TASKS) does NOT advertise them.
    assert "tasks" not in MCPServer().handle_initialize({})["capabilities"]


def test_long_tools_declare_task_support():
    by_name = {t["name"]: t for t in TOOLS}
    assert by_name["maverick_start"]["execution"]["taskSupport"] == "optional"
    assert by_name["maverick_resume"]["execution"]["taskSupport"] == "optional"
    # A fast, non-augmentable tool doesn't declare execution.
    assert "execution" not in by_name["maverick_status"]


def test_task_augmented_call_returns_create_task_result(monkeypatch):
    s = MCPServer()
    s._stdio = True
    s._tasks_enabled = True
    monkeypatch.setattr(s, "_task_runner", lambda name, args: _ok(f"ran {name}"))
    out = s.handle_tools_call({
        "name": "maverick_start",
        "arguments": {"title": "x"},
        "task": {"ttl": 60000},
    })
    assert set(out) == {"task"}
    assert out["task"]["status"] == "working"
    task_id = out["task"]["taskId"]
    try:
        res = s._task_store().result(task_id)
        assert res["content"][0]["text"] == "ran maverick_start"
    finally:
        s._task_store().shutdown()


def test_task_augmenting_unsupported_tool_is_method_not_found():
    s = MCPServer()
    s._stdio = True
    s._tasks_enabled = True
    with pytest.raises(_ProtocolError) as ei:
        s.handle_tools_call({
            "name": "maverick_status", "arguments": {}, "task": {"ttl": 1000}})
    assert ei.value.code == -32601


def test_task_field_ignored_over_http(monkeypatch):
    # No stdio -> tasks capability absent -> the `task` field is ignored and the
    # call runs normally (spec rule for receivers without the capability).
    s = MCPServer()
    s._stdio = False
    monkeypatch.setattr(s, "_dispatch_tool", lambda name, args: "ran inline")
    out = s.handle_tools_call({
        "name": "maverick_start", "arguments": {"title": "x"}, "task": {"ttl": 1000}})
    assert "task" not in out
    assert out["content"][0]["text"] == "ran inline"


def test_task_runner_uses_isolated_instance(monkeypatch):
    # The worker runs the tool on a FRESH MCPServer so it can't clobber the main
    # server's per-call state or touch stdio.
    monkeypatch.setattr(MCPServer, "_dispatch_tool", lambda self, n, a: f"ran {n}")
    s = MCPServer()
    s._stdio = True
    s._structured_override = {"sentinel": True}
    out = s._task_runner("maverick_start", {"title": "x"})
    assert out["isError"] is False
    assert out["content"][0]["text"] == "ran maverick_start"
    assert s._structured_override == {"sentinel": True}  # untouched by the worker


# ---- full run() loop integration -------------------------------------------

def test_run_loop_task_create_then_result(monkeypatch):
    """initialize -> task-augmented tools/call -> CreateTaskResult, then
    tasks/result blocks for and returns the CallToolResult over the stdio loop.

    Driven in two run() passes: the taskId is minted by the first, so the
    tasks/result request in the second is fed the real id."""
    s = MCPServer()
    monkeypatch.setattr(s, "_task_runner", lambda name, args: _ok(f"result of {name}"))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)

    # Pass 1: initialize + task-augmented create.
    monkeypatch.setattr(sys, "stdin", io.StringIO("".join(json.dumps(m) + "\n" for m in [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25",
                    "capabilities": {"tasks": {"requests": {"tools": {"call": {}}}}}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "maverick_start", "arguments": {"title": "go"},
                    "task": {"ttl": 60000}}},
    ])))
    s.run()
    msgs = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    create = next(m for m in msgs if m.get("id") == 2)
    assert "task" in create["result"] and create["result"]["task"]["status"] == "working"
    task_id = create["result"]["task"]["taskId"]

    # second pass: tasks/result (blocks until the worker is terminal)
    out.truncate(0)
    out.seek(0)
    sys.stdin = io.StringIO(json.dumps(
        {"jsonrpc": "2.0", "id": 3, "method": "tasks/result",
         "params": {"taskId": task_id}}) + "\n")
    s.run()
    res_msgs = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    result = next(m for m in res_msgs if m.get("id") == 3)["result"]
    assert result["content"][0]["text"] == "result of maverick_start"
    assert result["_meta"][RELATED_TASK_META] == {"taskId": task_id}
    if s._tasks is not None:
        s._tasks.shutdown()


# ---- notifications/tasks/status ---------------------------------------------

def test_status_callback_fires_on_completion():
    fired: list[tuple[str, str]] = []
    cb_done = threading.Event()

    def cb(task):
        fired.append((task.id, task.status))
        cb_done.set()

    store = TaskStore(lambda n, a: _ok("x"), on_status_change=cb)
    try:
        task = store.create("maverick_start", {}, {})
        store.result(task.id)  # terminal
        assert cb_done.wait(2)  # callback runs on the worker thread, just after
        assert fired[-1] == (task.id, "completed")
    finally:
        store.shutdown()


def test_status_callback_fires_on_failure():
    fired: list[str] = []
    cb_done = threading.Event()

    def cb(task):
        fired.append(task.status)
        cb_done.set()

    store = TaskStore(
        lambda n, a: {"isError": True, "content": [{"type": "text", "text": "boom"}]},
        on_status_change=cb)
    try:
        task = store.create("maverick_start", {}, {})
        store.result(task.id)
        assert cb_done.wait(2)
        assert fired[-1] == "failed"
    finally:
        store.shutdown()


def test_status_callback_fires_on_cancel():
    fired: list[str] = []
    release = threading.Event()
    store = TaskStore(
        lambda n, a: (release.wait(timeout=5), _ok("late"))[1],
        on_status_change=lambda t: fired.append(t.status))
    try:
        task = store.create("maverick_start", {}, {"ttl": 60000})
        store.cancel(task.id)  # cancel notifies synchronously on this thread
        assert fired == ["cancelled"]
    finally:
        release.set()
        store.shutdown()


def test_callback_error_does_not_break_the_task():
    def boom(_task):
        raise RuntimeError("notify exploded")

    store = TaskStore(lambda n, a: _ok("ok"), on_status_change=boom)
    try:
        task = store.create("maverick_start", {}, {})
        res = store.result(task.id)  # must still complete despite the bad callback
        assert res["content"][0]["text"] == "ok"
        assert store.get(task.id)["status"] == "completed"
    finally:
        store.shutdown()


def test_server_emits_well_formed_status_notification():
    s = MCPServer()
    s._stdio = True  # status push is stdio-only (HTTP clients poll)
    sent: list[dict] = []
    s._send = sent.append
    task = McpTask(ttl_ms=1000, poll_interval_ms=500)
    task.set_status("completed", "done")
    s._emit_task_status(task)
    assert len(sent) == 1
    msg = sent[0]
    assert msg["method"] == "notifications/tasks/status"
    assert "id" not in msg  # it's a notification, not a request
    assert msg["params"]["taskId"] == task.id
    assert msg["params"]["status"] == "completed"
    assert RELATED_TASK_META not in (msg["params"].get("_meta") or {})


def test_task_store_wires_the_status_callback():
    s = MCPServer()
    s._stdio = True
    store = s._task_store()
    try:
        assert store._on_status_change == s._emit_task_status
    finally:
        store.shutdown()


def test_run_loop_pushes_status_notification(monkeypatch):
    s = MCPServer()
    monkeypatch.setattr(s, "_task_runner", lambda n, a: _ok(f"done {n}"))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)

    def status_notification():
        for line in out.getvalue().splitlines():
            try:
                message = json.loads(line) if line.strip() else {}
            except json.JSONDecodeError:
                continue
            if message.get("method") == "notifications/tasks/status":
                return message
        return None

    class _ConnectedStdin:
        """The client stays connected until the push arrives (or 10 s pass).

        Pushes are stdio-only: once stdin reaches EOF the session is closed
        and a later completion is deliberately not written to the pipe, so an
        immediate EOF would race the worker."""

        def __init__(self, messages):
            self._lines = [json.dumps(m) + "\n" for m in messages]

        def readline(self):
            if self._lines:
                return self._lines.pop(0)
            deadline = time.monotonic() + 10
            while status_notification() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            return ""

    monkeypatch.setattr(sys, "stdin", _ConnectedStdin([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25",
                    "capabilities": {"tasks": {"requests": {"tools": {"call": {}}}}}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "maverick_start", "arguments": {"title": "go"},
                    "task": {"ttl": 60000}}},
    ]))
    s.run()
    try:
        notif = status_notification()
        assert notif is not None, "no notifications/tasks/status was pushed"
        assert notif["params"]["status"] == "completed"
    finally:
        if s._tasks is not None:
            s._tasks.shutdown()
