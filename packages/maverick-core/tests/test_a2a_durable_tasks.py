"""Cross-process A2A task claims and tenant isolation.

These tests exercise separate ``TaskEngine`` instances against the same
SQLite authority. They deliberately use an injected runner so no provider or
sandbox is touched.
"""
import asyncio
import sqlite3
import threading

import pytest
from maverick.a2a_tasks import TaskEngine, _RpcError
from maverick.file_lock import private_path_is_restricted
from maverick.paths import current_tenant_id, data_dir, reset_tenant, set_tenant


def _msg(text: str = "charge once", message_id: str = "durable-message-1") -> dict:
    return {
        "message": {
            "role": "user",
            "parts": [{"kind": "text", "text": text}],
            "messageId": message_id,
        }
    }


def test_terminal_result_survives_restart_and_replays_once(tmp_path):
    db = tmp_path / "a2a-tasks.sqlite3"
    calls: list[str] = []

    first_engine = TaskEngine(
        runner=lambda text, **kwargs: calls.append(text) or "settled",
        durable=True,
        state_path=db,
    )
    first = asyncio.run(first_engine.send(_msg(), "agent:alice"))

    restarted = TaskEngine(
        runner=lambda text, **kwargs: calls.append("duplicate") or "duplicate",
        durable=True,
        state_path=db,
    )
    replay = asyncio.run(restarted.send(_msg(), "agent:alice"))

    assert replay == first
    assert calls == ["charge once"]
    assert restarted.get({"id": first["id"]}, "agent:alice") == first
    assert private_path_is_restricted(db, 0o600)
    assert private_path_is_restricted(db.parent, 0o700)


def test_cross_instance_in_progress_claim_is_never_reexecuted(tmp_path):
    db = tmp_path / "a2a-tasks.sqlite3"
    calls: list[str] = []
    owner = TaskEngine(
        runner=lambda text, **kwargs: calls.append(text) or "settled",
        durable=True,
        state_path=db,
    )
    task, created = owner._new_or_existing_task(_msg(), "agent:alice")
    assert created is True

    contender = TaskEngine(
        runner=lambda text, **kwargs: calls.append("duplicate") or "duplicate",
        durable=True,
        state_path=db,
    )
    with pytest.raises(_RpcError, match="outcome is indeterminate"):
        asyncio.run(contender.send(_msg(), "agent:alice"))
    with pytest.raises(_RpcError, match="indeterminate"):
        contender.get({"id": task.id}, "agent:alice")
    with pytest.raises(_RpcError, match="different content"):
        asyncio.run(
            contender.send(_msg("changed", "durable-message-1"), "agent:alice")
        )
    assert calls == []

    # Once the original owner settles the exact claim, a fresh worker can
    # return that result without invoking its runner.
    asyncio.run(owner._run(task))
    restarted = TaskEngine(
        runner=lambda text, **kwargs: calls.append("duplicate") or "duplicate",
        durable=True,
        state_path=db,
    )
    replay = asyncio.run(restarted.send(_msg(), "agent:alice"))
    assert replay["id"] == task.id
    assert replay["status"]["state"] == "completed"
    assert calls == ["charge once"]


def test_simultaneous_engines_share_one_atomic_claim(tmp_path):
    db = tmp_path / "a2a-tasks.sqlite3"
    started = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    def runner(text, **kwargs):
        calls.append(text)
        started.set()
        release.wait(5)
        return "settled"

    owner = TaskEngine(runner=runner, durable=True, state_path=db)
    contender = TaskEngine(
        runner=lambda text, **kwargs: calls.append("duplicate") or "duplicate",
        durable=True,
        state_path=db,
    )

    async def drive():
        first = asyncio.create_task(owner.send(_msg(), "agent:alice"))
        while not started.is_set():
            await asyncio.sleep(0.001)
        second = asyncio.create_task(contender.send(_msg(), "agent:alice"))
        try:
            second_result = await second
        except _RpcError as exc:
            second_result = exc
        finally:
            release.set()
        return await first, second_result

    first, second = asyncio.run(drive())
    assert first["status"]["state"] == "completed"
    assert isinstance(second, _RpcError)
    assert "indeterminate" in second.message
    assert calls == ["charge once"]


def test_durable_claims_and_task_ownership_are_tenant_scoped(tmp_path):
    # A path override deliberately puts both tenants in one physical DB. The
    # tenant column must still isolate claims and task reads as defense in depth.
    db = tmp_path / "shared-a2a-tasks.sqlite3"
    calls: list[str] = []
    engine = TaskEngine(
        runner=lambda text, **kwargs: calls.append(text) or "ok",
        durable=True,
        state_path=db,
    )

    alpha_token = set_tenant("alpha")
    try:
        alpha = asyncio.run(engine.send(_msg(), "agent:alice"))
    finally:
        reset_tenant(alpha_token)

    beta_token = set_tenant("beta")
    try:
        beta = asyncio.run(engine.send(_msg(), "agent:alice"))
        with pytest.raises(_RpcError, match="task not found"):
            engine.get({"id": alpha["id"]}, "agent:alice")
    finally:
        reset_tenant(beta_token)

    alpha_token = set_tenant("alpha")
    try:
        assert engine.get({"id": alpha["id"]}, "agent:alice")["id"] == alpha["id"]
        with pytest.raises(_RpcError, match="task not found"):
            engine.get({"id": beta["id"]}, "agent:alice")
    finally:
        reset_tenant(alpha_token)

    assert alpha["id"] != beta["id"]
    assert calls == ["charge once", "charge once"]


def test_default_durable_path_is_resolved_per_request_tenant():
    calls: list[str] = []
    # Construct before either tenant is active. A frozen import/init-time path
    # would incorrectly place both claims in the shared root.
    engine = TaskEngine(
        runner=lambda text, **kwargs: calls.append(text) or "ok",
        durable=True,
    )

    alpha_token = set_tenant("alpha")
    try:
        alpha = asyncio.run(engine.send(_msg(), "agent:alice"))
        alpha_db = data_dir("a2a", "tasks.sqlite3")
    finally:
        reset_tenant(alpha_token)

    beta_token = set_tenant("beta")
    try:
        beta = asyncio.run(engine.send(_msg(), "agent:alice"))
        beta_db = data_dir("a2a", "tasks.sqlite3")
    finally:
        reset_tenant(beta_token)

    assert alpha_db != beta_db
    assert alpha_db.is_file() and beta_db.is_file()
    assert alpha["id"] != beta["id"]
    assert calls == ["charge once", "charge once"]


def test_deferred_task_execution_rebinds_captured_tenant():
    seen: list[str | None] = []
    engine = TaskEngine(
        runner=lambda text, **kwargs: seen.append(current_tenant_id()) or "ok",
    )
    token = set_tenant("alpha")
    try:
        task = engine._new_task(_msg(), "agent:alice")
    finally:
        reset_tenant(token)

    # Model deferred execution after request middleware has reset its pin.
    asyncio.run(engine._run(task))

    assert task.tenant == "alpha"
    assert seen == ["alpha"]


def test_stream_uses_explicit_request_time_tenant_pin():
    seen: list[str | None] = []
    engine = TaskEngine(
        runner=lambda text, **kwargs: seen.append(current_tenant_id()) or "ok",
    )

    async def collect():
        return [
            event
            async for event in engine.stream(
                _msg(), "agent:alice", tenant="alpha",
            )
        ]

    events = asyncio.run(collect())

    assert events[-1]["status"]["state"] == "completed"
    assert seen == ["alpha"]


def test_unreadable_durable_authority_fails_closed_before_runner(tmp_path):
    db = tmp_path / "a2a-tasks.sqlite3"
    db.write_bytes(b"not a sqlite database")
    calls: list[str] = []
    engine = TaskEngine(
        runner=lambda text, **kwargs: calls.append(text) or "unsafe",
        durable=True,
        state_path=db,
    )

    with pytest.raises(_RpcError, match="claim state is unavailable"):
        asyncio.run(engine.send(_msg(), "agent:alice"))
    assert calls == []


def test_bounded_store_tombstone_never_reopens_message_id(tmp_path, monkeypatch):
    import maverick.a2a_tasks as a2a_tasks

    db = tmp_path / "a2a-tasks.sqlite3"
    # Force terminal result bodies out of the tiny test budget. The no-replay
    # claim must outlive its body and remain authoritative after restart.
    monkeypatch.setattr(a2a_tasks, "_MAX_DURABLE_RETAINED_BYTES", 1_200)
    calls: list[str] = []
    engine = TaskEngine(
        runner=lambda text, **kwargs: calls.append(text) or ("R" * 900),
        durable=True,
        state_path=db,
    )
    first = asyncio.run(engine.send(_msg(), "agent:alice"))
    assert first["status"]["state"] == "completed"

    restarted = TaskEngine(
        runner=lambda text, **kwargs: calls.append("duplicate") or "duplicate",
        durable=True,
        state_path=db,
    )
    with pytest.raises(_RpcError, match="already consumed"):
        asyncio.run(restarted.send(_msg(), "agent:alice"))
    assert calls == ["charge once"]


def test_durable_snapshots_honor_at_rest_encryption(tmp_path, monkeypatch):
    from maverick.crypto_at_rest import is_sealed_str

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    db = tmp_path / "a2a-tasks.sqlite3"
    calls: list[str] = []
    engine = TaskEngine(
        runner=lambda text, **kwargs: calls.append(text) or "private result",
        durable=True,
        state_path=db,
    )
    first = asyncio.run(engine.send(_msg("private prompt"), "agent:alice"))

    with sqlite3.connect(db) as conn:
        stored = conn.execute(
            "SELECT snapshot_json FROM a2a_task_claims",
        ).fetchone()[0]
    assert is_sealed_str(stored)
    assert "private prompt" not in stored
    assert "private result" not in stored
    assert b"durable-message-1" not in db.read_bytes()

    restarted = TaskEngine(
        runner=lambda text, **kwargs: calls.append("duplicate") or "duplicate",
        durable=True,
        state_path=db,
    )
    replay = asyncio.run(
        restarted.send(_msg("private prompt"), "agent:alice")
    )
    assert replay == first
    assert calls == ["private prompt"]


def test_encryption_enabled_refuses_legacy_plaintext_snapshot(tmp_path, monkeypatch):
    db = tmp_path / "a2a-tasks.sqlite3"
    calls: list[str] = []
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    engine = TaskEngine(
        runner=lambda text, **kwargs: calls.append(text) or "plaintext result",
        durable=True,
        state_path=db,
    )
    asyncio.run(engine.send(_msg(), "agent:alice"))

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    restarted = TaskEngine(
        runner=lambda text, **kwargs: calls.append("duplicate") or "duplicate",
        durable=True,
        state_path=db,
    )
    with pytest.raises(_RpcError, match="claim state is unavailable"):
        asyncio.run(restarted.send(_msg(), "agent:alice"))
    assert calls == ["charge once"]


def test_durable_snapshot_uses_captured_per_tenant_key(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "1")
    db = tmp_path / "shared-a2a-tasks.sqlite3"
    calls: list[str] = []
    token = set_tenant("alpha")
    try:
        engine = TaskEngine(
            runner=lambda text, **kwargs: calls.append(text) or "tenant secret",
            durable=True,
            state_path=db,
        )
        first = asyncio.run(engine.send(_msg(), "agent:alice"))
    finally:
        reset_tenant(token)

    # Re-entering alpha after the original request ended can open its result.
    token = set_tenant("alpha")
    try:
        restarted = TaskEngine(
            runner=lambda text, **kwargs: calls.append("duplicate") or "duplicate",
            durable=True,
            state_path=db,
        )
        replay = asyncio.run(restarted.send(_msg(), "agent:alice"))
    finally:
        reset_tenant(token)
    assert replay == first

    # The same task id is not even addressable from beta's tenant namespace.
    token = set_tenant("beta")
    try:
        with pytest.raises(_RpcError, match="task not found"):
            restarted.get({"id": first["id"]}, "agent:alice")
    finally:
        reset_tenant(token)
    assert calls == ["charge once"]


def test_claim_digest_and_runner_input_share_one_immutable_copy():
    params = _msg("original")
    engine = TaskEngine(runner=lambda text, **kwargs: text)
    task = engine._new_task(params, "agent:alice")

    params["message"]["parts"][0]["text"] = "mutated after claim"

    assert task.messages[0]["parts"][0]["text"] == "original"
    result = asyncio.run(engine._run(task))
    assert result is None
    assert task.artifacts[0]["parts"][0]["text"] == "original"


def test_mounted_a2a_endpoint_uses_durable_engine_by_default(monkeypatch):
    pytest.importorskip("fastapi")
    import maverick.a2a as a2a
    import maverick.a2a_tasks as a2a_tasks
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    calls: list[str] = []
    monkeypatch.setenv("MAVERICK_A2A_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_A2A_TOKEN", "a2a-token")
    monkeypatch.setattr(
        a2a_tasks,
        "_default_runner",
        lambda text, **kwargs: calls.append(text) or "settled",
    )
    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": _msg(),
    }
    headers = {"Authorization": "Bearer a2a-token"}

    first_app = FastAPI()
    a2a.mount(first_app)
    first = TestClient(first_app).post("/a2a/v1", headers=headers, json=rpc).json()

    # A separately mounted app constructs a separate TaskEngine, modeling a
    # process restart or another application worker against the same tenant DB.
    restarted_app = FastAPI()
    a2a.mount(restarted_app)
    replay = TestClient(restarted_app).post(
        "/a2a/v1", headers=headers, json=rpc,
    ).json()

    assert replay["result"] == first["result"]
    assert calls == ["charge once"]


def test_mounted_stream_captures_tenant_before_response_iteration(monkeypatch):
    pytest.importorskip("fastapi")
    import maverick.a2a as a2a
    import maverick.a2a_tasks as a2a_tasks
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    captured: list[str | None] = []
    original_stream = a2a_tasks.TaskEngine.stream

    async def recording_stream(self, params, principal="anon", *, tenant=None):
        captured.append(tenant)
        async for event in original_stream(
            self, params, principal, tenant=tenant,
        ):
            yield event

    monkeypatch.setattr(a2a_tasks.TaskEngine, "stream", recording_stream)
    monkeypatch.setattr(a2a_tasks, "_default_runner", lambda text, **kwargs: "ok")
    monkeypatch.setenv("MAVERICK_A2A_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_A2A_TOKEN", "a2a-token")

    app = FastAPI()

    @app.middleware("http")
    async def pin_tenant(request, call_next):
        token = set_tenant("stream-tenant")
        try:
            return await call_next(request)
        finally:
            reset_tenant(token)

    a2a.mount(app)
    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/stream",
        "params": _msg(message_id="stream-tenant-message"),
    }
    response = TestClient(app).post(
        "/a2a/v1",
        headers={"Authorization": "Bearer a2a-token"},
        json=rpc,
    )

    assert response.status_code == 200
    assert "completed" in response.text
    assert captured == ["stream-tenant"]
