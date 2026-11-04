"""A run started from a chat form waits, at most half a second, for its page.

After Send the browser loads ``/chat/goal/<id>`` while the run builds its
agent; under one interpreter lock that page took about 560 ms instead of 120.
"""
from __future__ import annotations

import asyncio
import threading
import time

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import page_handoff

_ORIGIN = {"origin": "http://127.0.0.1"}


@pytest.fixture(autouse=True)
def _fresh_registry(monkeypatch):
    monkeypatch.setattr(page_handoff, "_pending", {})


def _timed_wait(goal_id, timeout):
    started = time.monotonic()
    asyncio.run(page_handoff.wait(goal_id, timeout=timeout))
    return time.monotonic() - started


def test_a_page_served_while_the_run_waits_starts_it_at_once():
    page_handoff.expect(7)
    threading.Timer(0.05, page_handoff.served, args=(7,)).start()
    assert _timed_wait(7, 5.0) < 2.0
    assert page_handoff._pending == {}


def test_a_page_served_before_the_run_waits_does_not_hold_it():
    page_handoff.expect(8)
    page_handoff.served(8)
    assert _timed_wait(8, 5.0) < 0.5
    assert page_handoff._pending == {}


def test_a_page_never_served_holds_the_run_only_up_to_the_limit():
    page_handoff.expect(9)
    assert 0.15 <= _timed_wait(9, 0.2) < 2.0
    assert page_handoff._pending == {}


def test_a_run_nobody_expects_a_page_for_never_waits():
    page_handoff.served(10)  # nothing to release: no error, nothing kept
    assert _timed_wait(10, 5.0) < 0.5
    assert page_handoff._pending == {}


def test_expectations_no_run_claimed_are_forgotten(monkeypatch):
    page_handoff.expect(11)
    page_handoff._pending[11]["since"] -= page_handoff._FORGET_AFTER_SECONDS + 1
    page_handoff.expect(12)
    assert set(page_handoff._pending) == {12}


def _prep(monkeypatch, tmp_path, started):
    from maverick import world_model
    from maverick_dashboard import app as dash_app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # a provider is configured
    import maverick.attachments as att
    monkeypatch.setattr(att, "DEFAULT_ROOT", tmp_path / "attachments")

    async def run(goal_id, *args, **kwargs):
        started.append((goal_id, time.monotonic()))

    monkeypatch.setattr("maverick.runner.run_goal_in_background_async", run)
    dash_app._world_cache.clear()


def _send():
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1").post("/chat/send", data={"title": "summarize this", "description": ""},
                                headers=_ORIGIN, follow_redirects=False)


def test_the_task_page_starts_the_run_it_was_waiting_for(monkeypatch, tmp_path):
    from maverick_dashboard.app import app

    started, sent = [], []
    _prep(monkeypatch, tmp_path, started)
    monkeypatch.setattr(page_handoff, "WAIT_SECONDS", 10.0)
    sender = threading.Thread(target=lambda: sent.append(_send()), daemon=True)
    sender.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not any(e["wake"] for e in page_handoff._pending.values()):
        time.sleep(0.01)
    [(goal_id, entry)] = page_handoff._pending.items()
    assert entry["wake"] is not None and started == [], "the run waits for its page"
    page = TestClient(app, base_url="http://127.0.0.1").get(f"/chat/goal/{goal_id}", headers=_ORIGIN)
    served_at = time.monotonic()
    sender.join(timeout=8)
    assert page.status_code == 200 and sent[0].status_code == 303
    assert sent[0].headers["location"] == f"/chat/goal/{goal_id}"
    assert [gid for gid, _ in started] == [goal_id]
    assert started[0][1] - served_at < 5, "the page, not the ten-second limit, started the run"


def test_a_task_whose_page_is_never_opened_still_starts(monkeypatch, tmp_path):
    started = []
    _prep(monkeypatch, tmp_path, started)
    monkeypatch.setattr(page_handoff, "WAIT_SECONDS", 0.2)
    response = _send()
    assert response.status_code == 303
    assert [f"/chat/goal/{gid}" for gid, _ in started] == [response.headers["location"]]
    assert page_handoff._pending == {}
