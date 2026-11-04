"""Real-time SSE stream of goal events (/api/v1/goals/{id}/events/stream)."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated_world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    yield


def _goal_with_events(tmp_path, n, *, status=None):
    from maverick import world_model
    w = world_model.WorldModel(world_model.DEFAULT_DB)
    gid = w.create_goal("stream me", "")
    for i in range(n):
        w.append_event(gid, "coder", "status", f"step {i}")
    if status:
        w.set_goal_status(gid, status)
    return gid


def test_sse_event_format():
    from maverick_dashboard.api import _sse_event
    e = type("E", (), {"id": 7, "agent": "coder", "kind": "tool",
                       "content": "ran x", "ts": 1.0})()
    frame = _sse_event(e)
    assert frame.startswith("id: 7\n")
    assert "event: tool\n" in frame
    assert frame.endswith("\n\n")
    body = frame.split("data: ", 1)[1].split("\n", 1)[0]
    assert json.loads(body)["content"] == "ran x"


def test_stream_unknown_goal_404():
    assert client.get("/api/v1/goals/999999/events/stream").status_code == 404


def test_stream_emits_events_with_limit(tmp_path):
    gid = _goal_with_events(tmp_path, 3)
    resp = client.get(f"/api/v1/goals/{gid}/events/stream?limit=3")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    body = resp.text
    assert ": connected" in body
    assert body.count("event: status") == 3
    assert "step 0" in body and "step 2" in body


def test_stream_ends_on_terminal_status(tmp_path):
    gid = _goal_with_events(tmp_path, 2, status="done")
    # No limit: the stream drains the 2 events, then ends because the goal is
    # terminal. poll=0 keeps the tail loop from sleeping.
    resp = client.get(f"/api/v1/goals/{gid}/events/stream?poll=0")
    assert resp.status_code == 200
    body = resp.text
    assert body.count("event: status") == 2
    assert "event: end" in body
    assert '"status": "done"' in body


def test_stream_since_skips_old(tmp_path):
    gid = _goal_with_events(tmp_path, 3, status="done")
    # since=large -> no historical events; terminal status ends it immediately.
    resp = client.get(f"/api/v1/goals/{gid}/events/stream?since=100000&poll=0")
    assert resp.status_code == 200
    assert resp.text.count("event: status") == 0
    assert "event: end" in resp.text


def test_stream_drains_full_backlog_before_end(monkeypatch, tmp_path):
    """A terminal goal with more events than one poll batch must stream the
    WHOLE backlog before the end frame — not just the first batch."""
    from maverick_dashboard import api

    monkeypatch.setattr(api, "_SSE_MAX_BATCH", 5)
    gid = _goal_with_events(tmp_path, 12, status="done")
    resp = client.get(f"/api/v1/goals/{gid}/events/stream?poll=0")
    assert resp.status_code == 200
    body = resp.text
    assert body.count("event: status") == 12
    assert body.count("event: end") == 1
    # the end frame comes after the last backlog event, never before
    assert body.rfind("step 11") < body.rfind("event: end")


def test_stream_rejects_when_concurrency_cap_is_full(monkeypatch, tmp_path):
    from maverick_dashboard import api

    gid = _goal_with_events(tmp_path, 1)

    class FullSemaphore:
        def locked(self):
            return True

        async def acquire(self):  # pragma: no cover - route must not wait here
            raise AssertionError("should reject instead of acquiring")

    monkeypatch.setattr(api, "_get_sse_semaphore", lambda: FullSemaphore())
    resp = client.get(f"/api/v1/goals/{gid}/events/stream")
    assert resp.status_code == 503
    assert resp.headers["retry-after"] == "5"


def test_stream_poll_parameter_does_not_control_sleep(monkeypatch, tmp_path):
    from maverick_dashboard import api

    gid = _goal_with_events(tmp_path, 0, status="done")
    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(api.asyncio, "sleep", fake_sleep)
    resp = client.get(f"/api/v1/goals/{gid}/events/stream?poll=0")
    assert resp.status_code == 200
    assert "event: end" in resp.text
    assert sleeps == []


def test_stream_pushes_the_answer_preview_without_an_event(monkeypatch, tmp_path):
    """The model's answer lands in ``result`` while the goal is still running
    (agent._PartialAnswerStream). The stream must push it as soon as it
    changes, without waiting for an event row, and the terminal payload must
    carry the final text.

    The writer replaces a preview only after the stream has read it. On a
    fixed 0.8 s timer it raced the stream's first read: when the request took
    longer than that to reach the read (a loaded CI worker, or the first
    request in a process), the first frame correctly carried a later preview."""
    import threading

    from maverick import world_model
    from maverick_dashboard import _event_stream

    w = world_model.WorldModel(world_model.DEFAULT_DB)
    gid = w.create_goal("stream me", "")
    w.set_goal_status(gid, "running")
    assert w.set_goal_partial_result(gid, "Hello, I am") is True

    # The stream builds every frame from this read; note each preview it sees.
    read_state = _event_stream.stream_state
    read = {"Hello, I am": threading.Event(), "Hello, I am still writing": threading.Event()}

    def stream_state(world, goal_id, *, include_result=False):
        state = read_state(world, goal_id, include_result=include_result)
        if include_result and state.result in read:
            read[state.result].set()
        return state

    monkeypatch.setattr(_event_stream, "stream_state", stream_state)
    unread = []

    def writer():
        if not read["Hello, I am"].wait(30):
            unread.append("Hello, I am")
        w.set_goal_partial_result(gid, "Hello, I am still writing")
        if not read["Hello, I am still writing"].wait(30):
            unread.append("Hello, I am still writing")
        w.set_goal_status(gid, "done", "Hello, I am done.")

    threading.Thread(target=writer, daemon=True).start()
    payloads = []
    with client.stream("GET", f"/api/goal/{gid}/events/stream") as r:
        assert r.status_code == 200
        for line in r.iter_lines():
            if line.startswith("data: "):
                payloads.append(json.loads(line[6:]))
            if payloads and payloads[-1].get("terminal") is True:
                break
    assert unread == []                                    # the stream read each preview in turn
    results = [p["result"] for p in payloads]
    assert results[0] == "Hello, I am"                     # first tick: the preview already there
    assert "Hello, I am still writing" in results          # pushed on change, no event needed
    assert payloads[-1]["terminal"] is True
    assert payloads[-1]["result"] == "Hello, I am done."
    assert all(p["events"] == [] for p in payloads)


def test_partial_result_never_overwrites_a_finished_goal(tmp_path):
    from maverick import world_model

    w = world_model.WorldModel(world_model.DEFAULT_DB)
    gid = w.create_goal("finished", "")
    w.set_goal_status(gid, "done", "final answer")
    assert w.set_goal_partial_result(gid, "late preview") is False
    assert w.get_goal(gid).result == "final answer"
