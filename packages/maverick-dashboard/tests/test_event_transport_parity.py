"""Durable replay cursors and terminal draining agree across transports."""
from __future__ import annotations

import json

import pytest
from maverick_dashboard import api, auth
from maverick_dashboard import app as dashboard
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request


@pytest.fixture
def event_world(tmp_path, monkeypatch):
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(api, "_world", lambda: world)
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    monkeypatch.setattr(api, "assert_goal_access", lambda *args: None)
    monkeypatch.setattr(dashboard, "assert_goal_access", lambda *args: None)
    monkeypatch.setattr(auth, "websocket_authorized", lambda *args: True)
    monkeypatch.setattr(dashboard, "can_access_goal_principal", lambda *args: True)
    yield world
    world.close()


async def _connected():
    return False


async def _unexpected_sleep(delay):
    raise AssertionError("terminal replay must end without sleeping")


def _request(last_id=None):
    headers = [(b"last-event-id", str(last_id).encode())] if last_id else []
    request = Request({"type": "http", "method": "GET", "scheme": "http", "path": "/events", "headers": headers})
    request.is_disconnected = _connected
    return request


def _goal(world, n=3, status="done"):
    goal_id = world.create_goal("vendor evidence", "")
    for i in range(n):
        world.append_event(goal_id, "reviewer", "evidence", f"version {i}")
    world.set_goal_status(goal_id, status)
    return goal_id


@pytest.mark.asyncio
async def test_v1_sse_honors_last_event_id(event_world):
    goal_id = _goal(event_world)
    old_id = event_world.goal_events(goal_id)[1].id
    response = await api.goal_events_stream(_request(old_id), goal_id)
    body = "".join([frame async for frame in response.body_iterator])
    assert "version 0" not in body and "version 1" not in body
    assert "version 2" in body


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["done", "completed", "failed", "cancelled", "blocked", "error"])
@pytest.mark.parametrize("surface", ["v1", "legacy"])
async def test_sse_terminal_status_parity(event_world, monkeypatch, status, surface):
    monkeypatch.setattr(api.asyncio, "sleep", _unexpected_sleep)
    goal_id = _goal(event_world, status=status)
    route = api.goal_events_stream if surface == "v1" else dashboard.api_goal_events_stream
    response = await route(_request(), goal_id)
    body = "".join([frame async for frame in response.body_iterator])
    assert f'"status": "{status}"' in body
    assert ("event: end" if surface == "v1" else "event: terminal") in body


class Socket:
    def __init__(self, since=0):
        self.query_params = {"since_id": str(since)}
        self.frames = []

    async def accept(self):
        pass

    async def close(self, **kwargs):
        pass

    async def send_json(self, value):
        self.frames.append(value)


@pytest.mark.asyncio
async def test_websocket_drains_terminal_backlog(event_world):
    goal_id = _goal(event_world, n=503)
    socket = Socket()
    await dashboard.run_events_firehose(socket, goal_id, principal=None)
    events = [frame for frame in socket.frames if frame["kind"] == "evidence"]
    assert len(events) == 503
    assert events[-1]["content"] == "version 502"
    assert socket.frames[-1]["content"] == "done"


@pytest.mark.asyncio
async def test_websocket_control_frame_never_advances_durable_cursor(event_world):
    goal_id = _goal(event_world, n=1)
    socket = Socket()
    await dashboard.run_events_firehose(socket, goal_id, principal=None)
    cursor = socket.frames[-1]["id"]
    event_world.set_goal_status(goal_id, "active")
    event_world.append_event(goal_id, "reviewer", "evidence", "renewed evidence")
    event_world.set_goal_status(goal_id, "done")
    reconnect = Socket(since=cursor)
    await dashboard.run_events_firehose(reconnect, goal_id, principal=None)
    assert any(frame.get("content") == "renewed evidence" for frame in reconnect.frames)


@pytest.mark.asyncio
async def test_websocket_blocked_status_ends_stream(event_world, monkeypatch):
    monkeypatch.setattr(api.asyncio, "sleep", _unexpected_sleep)
    goal_id = _goal(event_world, status="blocked")
    socket = Socket()
    await dashboard.run_events_firehose(socket, goal_id, principal=None)
    assert socket.frames[-1]["content"] == "blocked"


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["v1", "legacy"])
async def test_polling_terminal_only_after_replay_is_drained(event_world, surface):
    goal_id = _goal(event_world)
    route = api.goal_events if surface == "v1" else dashboard.api_goal_events_legacy
    first = await run_in_threadpool(route, _request(), goal_id, limit=2)
    first = first.model_dump() if hasattr(first, "model_dump") else first
    assert first["has_more"] and not first["terminal"]
    last = await run_in_threadpool(route, _request(), goal_id, since=first["next_id"], limit=2)
    last = last.model_dump() if hasattr(last, "model_dump") else last
    assert not last["has_more"] and last["terminal"]
    assert len(first["events"]) + len(last["events"]) == 3
    assert json.dumps(last)


@pytest.mark.asyncio
async def test_customer_activity_is_plain_across_transports_and_retains_durable_evidence(event_world):
    goal_id = _goal(event_world, n=0, status="blocked")
    raw = [
        ("plan", "role=orchestrator depth=0 brief=INTERNAL PROMPT ## Prior failures"),
        ("observation", "private model scratch text"),
        ("observation", "tool=ask_user -> <tool_output tool='ask_user'>QUEUED question #2</tool_output>"),
        ("error", "RuntimeError: private diagnostic C:\\server\\secret.log"),
        ("finding", "The invoice matches the approved purchase order."),
    ]
    for kind, content in raw:
        event_world.append_event(goal_id, "reviewer", kind, content)
    event_world.set_goal_status(goal_id, "blocked", "Stopped: the assistant ran into an error. maverick resume 7")
    outputs = []
    for route in (api.goal_events, dashboard.api_goal_events_legacy):
        value = await run_in_threadpool(route, _request(), goal_id)
        outputs.append(json.dumps(value.model_dump() if hasattr(value, "model_dump") else value))
    for route in (api.goal_events_stream, dashboard.api_goal_events_stream):
        response = await route(_request(), goal_id)
        outputs.append("".join([frame async for frame in response.body_iterator]))
    socket = Socket()
    await dashboard.run_events_firehose(socket, goal_id, principal=None)
    outputs.append(json.dumps(socket.frames))
    for output in outputs:
        assert "Requested more information from you." in output
        assert "The invoice matches the approved purchase order." in output
        for marker in ("INTERNAL PROMPT", "private model scratch", "tool_output", "QUEUED", "private diagnostic", "maverick resume"):
            assert marker not in output
    assert [(e.kind, e.content) for e in event_world.goal_events(goal_id)] == raw


@pytest.mark.asyncio
async def test_goal_waiting_for_an_answer_is_held_open_only_by_the_rest_poll(event_world, monkeypatch):
    """Transport contract (docs/api.md): a goal parked on a question is
    ``blocked``. GET /api/v1/goals/{id}/events says so with ``terminal: false``
    and ``needs_input: true``; the push streams and the older browser poller
    still end at ``blocked`` (a stream cannot be held open for a person's
    answer), so a client that sees one end reads ``needs_input`` from the REST
    goal instead."""
    monkeypatch.setattr(api.asyncio, "sleep", _unexpected_sleep)
    goal_id = _goal(event_world, status="blocked")
    question_id = event_world.ask("Which market first?", goal_id=goal_id)

    poll = await run_in_threadpool(api.goal_events, _request(), goal_id)
    assert poll.status == "blocked"
    assert (poll.terminal, poll.needs_input, poll.open_question_ids) == (False, True, [question_id])
    goal = api._to_goal_out(event_world.get_goal(goal_id))
    assert (goal.needs_input, goal.open_question_ids) == (True, [question_id])

    response = await api.goal_events_stream(_request(), goal_id)
    body = "".join([frame async for frame in response.body_iterator])
    assert "event: end" in body and '"status": "blocked"' in body

    legacy = await run_in_threadpool(dashboard.api_goal_events_legacy, _request(), goal_id)
    assert legacy["status"] == "blocked" and legacy["terminal"] is True

    socket = Socket()
    await dashboard.run_events_firehose(socket, goal_id, principal=None)
    assert socket.frames[-1]["content"] == "blocked" and socket.frames[-1]["terminal"] is True

    # Answering lets the task carry on: the same poll then stops reporting it.
    event_world.answer(question_id, "US")
    event_world.set_goal_status(goal_id, "blocked", result="stopped")
    again = await run_in_threadpool(api.goal_events, _request(), goal_id)
    assert (again.terminal, again.needs_input, again.open_question_ids) == (True, False, [])
