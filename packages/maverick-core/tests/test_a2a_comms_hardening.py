"""Regression coverage for A2A fleet-communication hardening."""
from __future__ import annotations

import asyncio
import threading
import uuid

import pytest
from maverick import a2a_tasks as a2at
from maverick.a2a_tasks import TaskEngine, _RpcError


def _msg(text: str, message_id: str | None = None) -> dict:
    return {
        "message": {
            "role": "user",
            "parts": [{"kind": "text", "text": text}],
            "messageId": message_id or uuid.uuid4().hex,
        }
    }


def test_cancelled_send_is_durably_terminal():
    started = threading.Event()
    release = threading.Event()

    def runner(text, **kwargs):
        started.set()
        release.wait(5)
        return "late result"

    engine = TaskEngine(runner=runner)

    async def drive():
        request = asyncio.create_task(engine.send(_msg("slow")))
        while not started.is_set():
            await asyncio.sleep(0.001)
        request.cancel()
        try:
            with pytest.raises(asyncio.CancelledError):
                await request
            task = next(iter(engine._tasks.values()))
            assert task.state == "canceled"
            assert task.status_history[-1]["state"] == "canceled"
        finally:
            release.set()

    asyncio.run(drive())
    assert next(iter(engine._tasks.values())).state == "canceled"


def test_canceled_semaphore_waiter_never_reaches_runner(monkeypatch):
    monkeypatch.setenv("MAVERICK_A2A_MAX_CONCURRENCY", "1")
    a2at._RUN_SEMAPHORES.clear()
    first_started = threading.Event()
    release_first = threading.Event()
    calls: list[str] = []

    def runner(text, **kwargs):
        calls.append(text)
        if text == "first":
            first_started.set()
            release_first.wait(5)
        return f"done:{text}"

    engine = TaskEngine(runner=runner)

    async def drive():
        first = asyncio.create_task(engine.send(_msg("first", "first-id")))
        while not first_started.is_set():
            await asyncio.sleep(0.001)
        second = asyncio.create_task(engine.send(_msg("second", "second-id")))
        while len(engine._tasks) < 2:
            await asyncio.sleep(0.001)
        second_record = next(
            task
            for task in engine._tasks.values()
            if task.messages[0]["messageId"] == "second-id"
        )
        engine.cancel({"id": second_record.id})
        release_first.set()
        first_result, second_result = await asyncio.gather(first, second)
        return first_result, second_result

    first_result, second_result = asyncio.run(drive())
    assert first_result["status"]["state"] == "completed"
    assert second_result["status"]["state"] == "canceled"
    assert calls == ["first"]


def test_tasks_cancel_during_runner_cannot_be_resurrected_to_completed():
    started = threading.Event()
    release = threading.Event()

    def runner(text, **kwargs):
        started.set()
        release.wait(5)
        return "must be discarded"

    engine = TaskEngine(runner=runner)

    async def drive():
        request = asyncio.create_task(engine.send(_msg("running", "running-id")))
        while not started.is_set():
            await asyncio.sleep(0.001)
        record = next(iter(engine._tasks.values()))
        assert engine.cancel({"id": record.id})["status"]["state"] == "canceled"
        release.set()
        return await request

    result = asyncio.run(drive())
    assert result["status"]["state"] == "canceled"
    assert result["artifacts"] == []


def test_closing_stream_marks_submitted_task_canceled():
    engine = TaskEngine(runner=lambda text, **kwargs: "unused")

    async def drive():
        stream = engine.stream(_msg("stream"))
        first = await anext(stream)
        await stream.aclose()
        return first["id"]

    task_id = asyncio.run(drive())
    assert engine._tasks[task_id].state == "canceled"


@pytest.mark.parametrize(
    "config",
    [
        "not-an-object",
        ["not-an-object"],
        {"url": ["https://93.184.216.34/hook"]},
        {"url": "https://93.184.216.34/hook", "token": 123},
        {"url": "https://93.184.216.34/hook\r\nX-Evil: yes"},
        {"url": "https://93.184.216.34/hook", "token": "bad\nheader"},
        {"url": "https://user:pass@93.184.216.34/hook"},  # pragma: allowlist secret
        {"url": "https://93.184.216.34/hook", "ignored": "field"},
        {"url": "https://93.184.216.34/" + "x" * 5000},
        {"url": "https://93.184.216.34/\ud800"},
    ],
)
def test_push_config_rejects_malformed_or_unbounded_values(config):
    engine = TaskEngine(runner=lambda text, **kwargs: "ok")
    task = engine._new_task(_msg("push"))
    with pytest.raises(_RpcError):
        engine.set_push_config({
            "taskId": task.id,
            "pushNotificationConfig": config,
        })
    assert task.push_config is None


def test_request_and_artifact_retention_are_bounded(monkeypatch):
    monkeypatch.setattr(a2at, "_MAX_REQUEST_RETAINED_BYTES", 512)
    monkeypatch.setattr(a2at, "_MAX_ARTIFACT_TEXT_BYTES", 128)
    monkeypatch.setattr(a2at, "_MAX_TASK_RETAINED_BYTES", 700)
    monkeypatch.setattr(a2at, "_MAX_TOTAL_RETAINED_BYTES", 1600)

    engine = TaskEngine(runner=lambda text, **kwargs: "R" * 10_000)
    for index in range(20):
        result = asyncio.run(engine.send(_msg(f"work-{index}", f"id-{index}")))
        retained_result = result["artifacts"][0]["parts"][0]["text"]
        assert len(retained_result.encode("utf-8")) <= 128

    assert engine._retained_bytes <= 1600
    assert engine._retained_bytes == sum(
        task.retained_bytes for task in engine._tasks.values()
    )
    assert all(task.retained_bytes <= 700 for task in engine._tasks.values())
    assert len(engine._tasks) < 20  # old terminal records were reclaimed

    with pytest.raises(_RpcError, match="retained-byte"):
        asyncio.run(engine.send(_msg("X" * 2000, "oversized-request")))
