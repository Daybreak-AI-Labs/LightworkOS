"""Functional robustness: SSE stream resume (Last-Event-ID) + client dedup.

Without resume support an EventSource reconnect (network blip, proxy
timeout, or the server's 300s lifetime cap) restarts from ``?since=`` and
replays the whole event log as duplicates. The stream now emits ``id:``
lines and honors ``Last-Event-ID``; the client also dedups by id.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _setup(monkeypatch, tmp_path):
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    return world_model.WorldModel(db)


def test_stream_emits_ids_and_retry(monkeypatch, tmp_path):
    w = _setup(monkeypatch, tmp_path)
    gid = w.create_goal("g", "d")
    w.append_event(gid, "planner", "plan", "first")
    e2 = w.append_event(gid, "worker", "finding", "second")
    w.set_goal_status(gid, "done", "all done")  # terminal so the stream ends
    r = _client().get(f"/api/goal/{gid}/events/stream")
    assert r.status_code == 200
    body = r.text
    assert "retry: 3000" in body          # advertised reconnect delay
    assert f"id: {e2}" in body            # last id, for Last-Event-ID resume
    assert "event: terminal" in body
    assert "first" in body and "second" in body


def test_stream_resumes_from_last_event_id(monkeypatch, tmp_path):
    w = _setup(monkeypatch, tmp_path)
    gid = w.create_goal("g", "d")
    w.append_event(gid, "planner", "plan", "alpha")
    e2 = w.append_event(gid, "worker", "finding", "bravo")
    w.append_event(gid, "worker", "finding", "charlie")
    w.set_goal_status(gid, "done")
    # Reconnect the way the browser does: Last-Event-ID = 2nd event's id.
    r = _client().get(
        f"/api/goal/{gid}/events/stream",
        headers={"Last-Event-ID": str(e2)},
    )
    assert r.status_code == 200
    body = r.text
    assert "charlie" in body       # only events after the resume point
    assert "alpha" not in body     # already-delivered events are not replayed
    assert "bravo" not in body


def test_malformed_last_event_id_is_ignored(monkeypatch, tmp_path):
    w = _setup(monkeypatch, tmp_path)
    gid = w.create_goal("g", "d")
    w.append_event(gid, "planner", "plan", "alpha")
    w.set_goal_status(gid, "done")
    r = _client().get(
        f"/api/goal/{gid}/events/stream",
        headers={"Last-Event-ID": "not-a-number"},
    )
    assert r.status_code == 200
    assert "alpha" in r.text  # bad header falls back to since=0, no crash


def test_goal_page_dedups_and_guards_payload(monkeypatch, tmp_path):
    w = _setup(monkeypatch, tmp_path)
    gid = w.create_goal("g", "d")
    r = _client().get(f"/chat/goal/{gid}")
    assert "lastSeenId" in r.text
    assert "Array.isArray(d.events)" in r.text
