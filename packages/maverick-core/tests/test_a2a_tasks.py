"""A2A task lifecycle: message/send, message/stream, tasks/get|cancel,
push config, auth, and budget clamping. Goals are faked via an injected
runner so these never touch an LLM or sandbox."""
import asyncio
import uuid

import pytest
from maverick.a2a_tasks import (
    _AUTH_REQUIRED,
    TaskEngine,
    _RpcError,
)


def _fake_runner(text, *, max_dollars, max_wall, max_depth):
    return f"did:{text} (<=${max_dollars})"


def _msg(text):
    return {
        "message": {
            "role": "user",
            "parts": [{"kind": "text", "text": text}],
            "messageId": str(uuid.uuid4()),
        }
    }


def _msg_id(text, message_id):
    params = _msg(text)
    params["message"]["messageId"] = message_id
    return params


def _collect(agen):
    async def _run():
        return [e async for e in agen]
    return asyncio.run(_run())


# ---- message/send ----------------------------------------------------

def test_send_completes_with_artifact():
    eng = TaskEngine(runner=_fake_runner)
    task = asyncio.run(eng.send(_msg("hello")))
    assert task["kind"] == "task"
    assert task["status"]["state"] == "completed"
    assert task["artifacts"][0]["parts"][0]["text"].startswith("did:hello")
    states = [s["state"] for s in task["metadata"]["statusHistory"]]
    assert states == ["submitted", "working", "completed"]
    # inbound message echoed into history with task/context ids stamped
    assert task["history"][0]["taskId"] == task["id"]


def test_empty_message_is_rejected():
    eng = TaskEngine(runner=_fake_runner)
    task = asyncio.run(eng.send(_msg("")))
    assert task["status"]["state"] == "rejected"


def test_missing_message_id_is_rejected_before_execution():
    eng = TaskEngine(runner=_fake_runner)

    with pytest.raises(_RpcError, match="messageId is required"):
        asyncio.run(
            eng.send(
                {"message": {"role": "user", "parts": [{"kind": "text", "text": "x"}]}}
            )
        )


def test_runner_failure_marks_failed():
    def boom(text, **k):
        raise RuntimeError("kaboom")
    eng = TaskEngine(runner=boom)
    task = asyncio.run(eng.send(_msg("hi")))
    assert task["status"]["state"] == "failed"
    assert "kaboom" in task["artifacts"][0]["parts"][0]["text"]


def test_message_id_is_principal_scoped_idempotency_key():
    calls = []

    def runner(text, **kwargs):
        calls.append(text)
        return f"ran:{text}"

    eng = TaskEngine(runner=runner)
    params = _msg_id("charge once", "message-123")
    first = asyncio.run(eng.send(params, "agent:alice"))
    replay = asyncio.run(eng.send(params, "agent:alice"))

    assert replay["id"] == first["id"]
    assert replay["status"]["state"] == "completed"
    assert calls == ["charge once"]

    # The same opaque ID belongs to a different idempotency namespace for Bob.
    bob = asyncio.run(eng.send(params, "agent:bob"))
    assert bob["id"] != first["id"]
    assert calls == ["charge once", "charge once"]


def test_message_id_reuse_with_different_content_is_rejected():
    eng = TaskEngine(runner=_fake_runner)
    asyncio.run(eng.send(_msg_id("first", "message-123"), "agent:alice"))

    with pytest.raises(_RpcError, match="different content"):
        asyncio.run(eng.send(_msg_id("changed", "message-123"), "agent:alice"))


def test_concurrent_duplicate_message_runs_once():
    calls = 0

    def runner(text, **kwargs):
        nonlocal calls
        calls += 1
        return "ok"

    eng = TaskEngine(runner=runner)
    params = _msg_id("once", "message-concurrent")

    async def drive():
        return await asyncio.gather(
            eng.send(params, "agent:alice"),
            eng.send(params, "agent:alice"),
        )

    first, second = asyncio.run(drive())
    assert first["id"] == second["id"]
    assert calls == 1


def test_task_capacity_never_evicts_active_tasks(monkeypatch):
    import maverick.a2a_tasks as a2at

    monkeypatch.setattr(a2at, "_MAX_TASKS", 2)
    eng = TaskEngine(runner=_fake_runner)
    first = eng._new_task(_msg_id("one", "m1"))
    second = eng._new_task(_msg_id("two", "m2"))

    with pytest.raises(_RpcError, match="capacity"):
        eng._new_task(_msg_id("three", "m3"))
    assert first.id in eng._tasks and second.id in eng._tasks

    first.set_state("completed")
    third = eng._new_task(_msg_id("three", "m3"))
    assert first.id not in eng._tasks
    assert second.id in eng._tasks and third.id in eng._tasks


# ---- message/stream --------------------------------------------------

def test_stream_event_sequence():
    eng = TaskEngine(runner=_fake_runner)
    events = _collect(eng.stream(_msg("go")))
    kinds = [e["kind"] for e in events]
    assert kinds[0] == "task"               # initial snapshot
    assert "status-update" in kinds
    assert "artifact-update" in kinds
    last = events[-1]
    assert last["kind"] == "status-update"
    assert last["final"] is True
    assert last["status"]["state"] == "completed"
    art = next(e for e in events if e["kind"] == "artifact-update")
    assert art["artifact"]["parts"][0]["text"].startswith("did:go")


# ---- tasks/get + tasks/cancel + push config --------------------------

def test_get_and_cancel():
    eng = TaskEngine(runner=_fake_runner)
    task = asyncio.run(eng.send(_msg("x")))
    tid = task["id"]
    assert eng.get({"id": tid})["id"] == tid
    # cancelling an already-terminal task leaves it terminal
    assert eng.cancel({"id": tid})["status"]["state"] == "completed"
    with pytest.raises(_RpcError):
        eng.get({"id": "nope"})


def test_non_string_task_id_is_not_found_not_crash():
    """A hostile client can send a non-string (unhashable) id/taskId. It must
    resolve to a clean 'task not found' _RpcError, never a TypeError from the
    dict lookup (which would escape to a 500)."""
    eng = TaskEngine(runner=_fake_runner)
    for bad in ([1, 2], {"a": 1}, [[{"x": 1}]], 42, None):
        for method in (eng.get, eng.cancel, eng.get_push_config):
            with pytest.raises(_RpcError):
                method({"id": bad, "taskId": bad})


def test_cancel_pending_task():
    eng = TaskEngine(runner=_fake_runner)
    t = eng._new_task(_msg("later"))  # created, not yet run
    assert eng.cancel({"id": t.id})["status"]["state"] == "canceled"


def test_push_config_set_and_get():
    eng = TaskEngine(runner=_fake_runner)
    t = eng._new_task(_msg("x"))
    # Literal public IP: registration-time SSRF check resolves it without DNS.
    cfg = {"url": "https://93.184.216.34/wh", "token": "abc"}
    res = eng.set_push_config({"taskId": t.id, "pushNotificationConfig": cfg})
    assert res["pushNotificationConfig"]["url"] == cfg["url"]
    # neither set nor get echoes the registered webhook token: a peer sharing
    # the single A2A bearer token could otherwise read another caller's secret.
    # The url is still returned; the token is masked.
    assert res["pushNotificationConfig"]["token"] == "***"
    got = eng.get_push_config({"taskId": t.id})["pushNotificationConfig"]
    assert got["url"] == cfg["url"]
    assert got["token"] == "***" and got["token"] != "abc"
    # ...but the real token stays in storage so _fire_push can authenticate.
    assert eng._tasks[t.id].push_config["token"] == "abc"
    with pytest.raises(_RpcError):  # url is required
        eng.set_push_config({"taskId": t.id, "pushNotificationConfig": {}})


def test_set_push_config_rejects_ssrf_url_at_registration():
    """A loopback/metadata push URL is refused at registration, never stored."""
    eng = TaskEngine(runner=_fake_runner)
    t = eng._new_task(_msg("x"))
    for url in (
        "http://127.0.0.1:8765/api/v1/killswitch",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
    ):
        with pytest.raises(_RpcError):
            eng.set_push_config(
                {"taskId": t.id, "pushNotificationConfig": {"url": url}},
            )
    assert eng._tasks[t.id].push_config is None


def test_tasks_are_scoped_to_principal():
    """Under unauthenticated/shared access, one principal must not read, cancel,
    or redirect another principal's task -- a cross-principal lookup 404s."""
    eng = TaskEngine(runner=_fake_runner)
    owner = TaskEngine.principal_for("Bearer alice")
    other = TaskEngine.principal_for("Bearer bob")
    assert owner != other
    task = asyncio.run(eng.send(_msg("x"), owner))
    tid = task["id"]
    # owner can read/cancel/configure
    assert eng.get({"id": tid}, owner)["id"] == tid
    # a different principal is rejected (404-shaped, not 403) on every path
    with pytest.raises(_RpcError):
        eng.get({"id": tid}, other)
    with pytest.raises(_RpcError):
        eng.cancel({"id": tid}, other)
    with pytest.raises(_RpcError):
        eng.get_push_config({"taskId": tid}, other)
    with pytest.raises(_RpcError):
        eng.set_push_config(
            {"taskId": tid,
             "pushNotificationConfig": {"url": "https://93.184.216.34/wh"}},
            other,
        )
    # the owner's task is untouched by the rejected cancel attempt
    assert eng.get({"id": tid}, owner)["status"]["state"] == "completed"


# ---- auth + budget clamping ------------------------------------------

def test_auth_model(monkeypatch):
    eng = TaskEngine(runner=_fake_runner)
    monkeypatch.delenv("MAVERICK_A2A_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_A2A_ALLOW_UNAUTHENTICATED", raising=False)
    # no token + no opt-out -> refuse
    err = eng.auth_error(None)
    assert err and err["code"] == _AUTH_REQUIRED
    # explicit localhost opt-out -> allowed
    monkeypatch.setenv("MAVERICK_A2A_ALLOW_UNAUTHENTICATED", "1")
    assert eng.auth_error(None) is None
    # token set -> bearer enforced
    monkeypatch.delenv("MAVERICK_A2A_ALLOW_UNAUTHENTICATED", raising=False)
    monkeypatch.setenv("MAVERICK_A2A_TOKEN", "sekret")
    assert eng.auth_error(None) is not None
    assert eng.auth_error("Bearer wrong") is not None
    assert eng.auth_error("Bearer sekret") is None


def _budget_recorder():
    captured = {}

    def rec(text, *, max_dollars, max_wall, max_depth):
        captured.update(d=max_dollars)
        return "ok"

    return rec, captured


def test_budget_defaults_to_ceiling_when_client_silent(monkeypatch):
    monkeypatch.setenv("MAVERICK_A2A_MAX_DOLLARS", "2.5")
    rec, captured = _budget_recorder()
    eng = TaskEngine(runner=rec)
    asyncio.run(eng.send(_msg("hi")))
    assert captured["d"] == 2.5


def test_client_budget_is_clamped_to_operator_ceiling(monkeypatch):
    """The CLIENT request is honoured but clamped to the operator ceiling --
    not the old tautology where the env var was both value and ceiling and the
    client request was ignored."""
    monkeypatch.setenv("MAVERICK_A2A_MAX_DOLLARS", "2.5")
    rec, captured = _budget_recorder()
    eng = TaskEngine(runner=rec)
    # client asks for LESS than the ceiling -> honoured (down)
    params = {**_msg("hi"), "configuration": {"max_dollars": 1.0}}
    asyncio.run(eng.send(params))
    assert captured["d"] == 1.0
    # client asks for MORE than the ceiling -> clamped to the operator max
    params = {**_msg("hi"), "configuration": {"max_dollars": 100.0}}
    asyncio.run(eng.send(params))
    assert captured["d"] == 2.5


# ---- push-notification SSRF guard ------------------------------------

def _spy_async_post(monkeypatch):
    """Replace AsyncClient.post with a spy; return the list it records into."""
    import httpx
    posted: list[str] = []

    async def _post(self, url, **kw):
        posted.append(str(url))

        class _R:
            status_code = 200

        return _R()

    monkeypatch.setattr(httpx.AsyncClient, "post", _post)
    return posted


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata
    "http://127.0.0.1:8765/api/v1/killswitch",   # loopback control surface
    "http://[::1]/",                             # loopback v6
    "file:///etc/passwd",                        # non-http scheme
])
def test_push_blocks_ssrf_to_internal_targets(monkeypatch, url):
    """A caller-supplied push URL pointing at an internal/non-public host must
    not result in an outbound request (SSRF guard, fail-closed)."""
    posted = _spy_async_post(monkeypatch)
    eng = TaskEngine(runner=_fake_runner)
    t = eng._new_task(_msg("x"))
    t.set_state("completed")
    t.push_config = {"url": url}
    asyncio.run(eng._fire_push(t))
    assert posted == []  # request was blocked before any connection


def test_push_stays_public_only_under_the_fetch_private_override(monkeypatch):
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    posted = _spy_async_post(monkeypatch)
    eng = TaskEngine(runner=_fake_runner)
    t = eng._new_task(_msg("x"))
    with pytest.raises(_RpcError) as caught:
        eng.set_push_config({"taskId": t.id, "pushNotificationConfig": {
            "url": "http://127.0.0.1:9/hook", "token": "tok"}})
    assert "127.0.0.1" not in str(caught.value)  # no resolver detail returned
    t.set_state("completed")
    t.push_config = {"url": "http://127.0.0.1:9/hook", "token": "tok"}
    asyncio.run(eng._fire_push(t))
    assert posted == []


def test_push_allows_public_host(monkeypatch):
    """A public push target still fires (the guard only blocks non-public)."""
    posted = _spy_async_post(monkeypatch)
    eng = TaskEngine(runner=_fake_runner)
    t = eng._new_task(_msg("x"))
    t.set_state("completed")
    # Literal public IP: no DNS, so this is deterministic offline.
    t.push_config = {"url": "http://93.184.216.34/wh"}
    asyncio.run(eng._fire_push(t))
    assert posted == ["http://93.184.216.34/wh"]


# ---- HTTP wiring (FastAPI) -------------------------------------------

def test_http_endpoint_send_and_card(monkeypatch):
    pytest.importorskip("fastapi")
    import maverick.a2a as a2a
    import maverick.a2a_tasks as a2at
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    monkeypatch.setattr(a2at, "_default_runner",
                        lambda text, **k: f"ran:{text}")
    monkeypatch.setenv("MAVERICK_A2A_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_A2A_TOKEN", "tok")
    monkeypatch.delenv("MAVERICK_A2A_ALLOW_UNAUTHENTICATED", raising=False)

    app = FastAPI()
    a2a.mount(app)
    client = TestClient(app)

    rpc = {"jsonrpc": "2.0", "id": 1, "method": "message/send",
           "params": _msg("hello")}
    # no bearer -> 401
    assert client.post("/a2a/v1", json=rpc).status_code == 401
    # Auth is checked before parsing hostile JSON.
    assert client.post(
        "/a2a/v1", content=b"{not-json", headers={"Content-Type": "application/json"}
    ).status_code == 401
    invalid = client.post(
        "/a2a/v1",
        headers={"Authorization": "Bearer tok"},
        json={"jsonrpc": "2.0", "id": 9, "method": "message/send", "params": []},
    )
    assert invalid.json()["error"]["code"] == -32600
    # with bearer -> completed task
    r = client.post("/a2a/v1", headers={"Authorization": "Bearer tok"}, json=rpc)
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["status"]["state"] == "completed"
    assert "ran:hello" in result["artifacts"][0]["parts"][0]["text"]

    # the card now advertises the backed capabilities
    card = client.get("/.well-known/agent-card.json").json()
    assert card["capabilities"]["streaming"] is True
    assert card["capabilities"]["pushNotifications"] is True
    assert card["url"].endswith("/a2a/v1")


def test_http_stream_emits_sse(monkeypatch):
    pytest.importorskip("fastapi")
    import maverick.a2a as a2a
    import maverick.a2a_tasks as a2at
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    monkeypatch.setattr(a2at, "_default_runner", lambda text, **k: f"ran:{text}")
    monkeypatch.setenv("MAVERICK_A2A_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_A2A_ALLOW_UNAUTHENTICATED", "1")
    monkeypatch.delenv("MAVERICK_A2A_TOKEN", raising=False)

    app = FastAPI()
    a2a.mount(app)
    client = TestClient(app)
    rpc = {"jsonrpc": "2.0", "id": 2, "method": "message/stream",
           "params": _msg("go")}
    r = client.post("/a2a/v1", json=rpc)
    assert r.status_code == 200
    body = r.text
    assert "status-update" in body
    assert "artifact-update" in body
    assert "ran:go" in body


def test_a2a_rejects_cross_origin_browser_request(monkeypatch):
    """/a2a/v1 must reject a browser cross-origin POST (DNS-rebinding defense),
    the same gate /mcp has. This is the ONLY browser defense when the bearer is
    waived via MAVERICK_A2A_ALLOW_UNAUTHENTICATED."""
    pytest.importorskip("fastapi")
    import maverick.a2a as a2a
    import maverick.a2a_tasks as a2at
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    monkeypatch.setattr(a2at, "_default_runner", lambda text, **k: f"ran:{text}")
    monkeypatch.setenv("MAVERICK_A2A_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_A2A_ALLOW_UNAUTHENTICATED", "1")  # bearer waived
    monkeypatch.delenv("MAVERICK_A2A_ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("MAVERICK_MCP_ALLOWED_ORIGINS", raising=False)

    app = FastAPI()
    a2a.mount(app)
    client = TestClient(app)
    rpc = {"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": _msg("hi")}

    # A malicious page's Origin -> blocked even though auth is waived.
    r = client.post("/a2a/v1", headers={"Origin": "https://evil.example"}, json=rpc)
    assert r.status_code == 403
    assert "cross-origin" in r.json()["error"]["message"]

    # A loopback Origin (a local browser client) is allowed.
    assert client.post("/a2a/v1", headers={"Origin": "http://127.0.0.1:8771"},
                       json=rpc).status_code == 200
    # No Origin (native client / curl / server-to-server) is allowed.
    assert client.post("/a2a/v1", json=rpc).status_code == 200
    # An explicit allow-list entry is honored.
    monkeypatch.setenv("MAVERICK_A2A_ALLOWED_ORIGINS", "https://trusted.example")
    assert client.post("/a2a/v1", headers={"Origin": "https://trusted.example"},
                       json=rpc).status_code == 200


# ---- concurrency cap -------------------------------------------------

def test_concurrent_goals_capped_to_max_concurrency(monkeypatch):
    """N concurrent message/send goals must not all execute at once: the
    MAVERICK_A2A_MAX_CONCURRENCY limiter bounds how many run on the shared
    default ThreadPoolExecutor simultaneously, so one caller can't saturate it.
    Without the limiter, the executor admits up to its full worker count and
    the observed peak exceeds the cap."""
    import threading

    monkeypatch.setenv("MAVERICK_A2A_MAX_CONCURRENCY", "2")

    state = {"live": 0, "peak": 0}
    lock = threading.Lock()
    # All runners are released together, so without a cap they'd all run at once.
    release = threading.Event()

    def runner(text, *, max_dollars, max_wall, max_depth):
        with lock:
            state["live"] += 1
            state["peak"] = max(state["peak"], state["live"])
        # Hold the slot long enough that later goals would pile on if uncapped.
        release.wait(timeout=2.0)
        with lock:
            state["live"] -= 1
        return f"ran:{text}"

    eng = TaskEngine(runner=runner)

    async def drive():
        tasks = [asyncio.create_task(eng.send(_msg(f"g{i}"))) for i in range(6)]
        # Give the workers a moment to climb to their peak, then release.
        await asyncio.sleep(0.3)
        release.set()
        return await asyncio.gather(*tasks)

    results = asyncio.run(drive())
    assert all(r["status"]["state"] == "completed" for r in results)
    assert state["peak"] <= 2, f"peak concurrency {state['peak']} exceeded cap 2"


def test_max_concurrency_zero_disables_cap(monkeypatch):
    """Setting the knob to 0 lifts the limiter (no slot acquisition), so a
    larger batch can run concurrently on the executor."""
    import threading

    monkeypatch.setenv("MAVERICK_A2A_MAX_CONCURRENCY", "0")

    state = {"live": 0, "peak": 0}
    lock = threading.Lock()
    release = threading.Event()

    def runner(text, *, max_dollars, max_wall, max_depth):
        with lock:
            state["live"] += 1
            state["peak"] = max(state["peak"], state["live"])
        release.wait(timeout=2.0)
        with lock:
            state["live"] -= 1
        return "ok"

    eng = TaskEngine(runner=runner)

    async def drive():
        tasks = [asyncio.create_task(eng.send(_msg(f"g{i}"))) for i in range(4)]
        await asyncio.sleep(0.3)
        release.set()
        return await asyncio.gather(*tasks)

    asyncio.run(drive())
    # The default executor on this box has >=4 workers; with the cap disabled
    # all 4 short goals overlap.
    assert state["peak"] >= 2


def test_a2a_task_failure_scrubs_exception_text():
    from maverick import a2a_tasks
    from maverick.secrets import scrub
    task = a2a_tasks._Task(
        "ctx", {"role": "user", "parts": [], "messageId": "m", "kind": "message"})
    # Mirror the fixed failure path: a connection error carrying a DSN secret.
    e = RuntimeError("connect failed: postgres://user:supersecretpw@db/app")
    detail = scrub(f"{type(e).__name__}: {e}")
    task.add_artifact(f"task failed: {detail}", "error")
    # The task dict is what reaches the caller and the push webhook.
    assert "supersecretpw" not in str(task.to_dict())
