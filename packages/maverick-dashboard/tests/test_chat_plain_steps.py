"""The conversation's work log narrates steps; the recording is folded under Technical details."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
BRIEF = "role=orchestrator depth=0 brief=Top-level goal: Summarize last quarter's vendor spend"


@pytest.fixture
def world(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    w = world_model.WorldModel(tmp_path / "world.db")
    yield w
    w.close()


def _goal(world):
    gid = world.create_goal("Summarize vendor spend", "")
    world.append_event(gid, "orchestrator-0-72eb85", "plan", BRIEF)
    world.append_event(gid, "orchestrator-0-72eb85", "observation", "tool=read_file -> vendor,amount")
    world.append_event(gid, "researcher-1-a1b2c3", "observation", "tool=read_file -> more rows")
    world.append_event(gid, "orchestrator-0-72eb85", "tool_signal", "search_replace_used=1")
    world.set_goal_status(gid, "done", result="Here is the summary.")
    return gid


def test_the_polling_payload_carries_a_plain_step_for_every_event(world):
    gid = _goal(world)
    events = client.get(f"/api/goal/{gid}/events").json()["events"]
    steps = [(e["step"]["text"], e["step"]["hidden"], e["who"]) for e in events]
    assert steps == [
        ("Started working on your request", False, "Planner"),
        ("Read a file", False, "Planner"),
        ("Read a file", False, "Researcher"),
        ("", True, "Planner"),
    ]
    # The page receives the owner's readable activity, never the internal brief
    # (the transport contract in test_event_transport_parity); the exact record
    # stays in the world store.
    assert events[0]["content"] == "Started work on this task."
    assert all(BRIEF not in e["content"] for e in events)


def test_the_live_stream_payload_carries_the_same_plain_steps(world):
    gid = _goal(world)
    with client.stream("GET", f"/api/goal/{gid}/events/stream") as response:
        body = "".join(response.iter_text())
    frames = [json.loads(line[len("data: "):]) for line in body.splitlines() if line.startswith("data: {")]
    texts = [e["step"]["text"] for frame in frames for e in frame.get("events", [])]
    assert texts[:2] == ["Started working on your request", "Read a file"]


def test_the_conversation_folds_the_step_record_under_its_own_disclosure(world):
    gid = _goal(world)
    body = client.get(f"/chat/goal/{gid}").text
    assert '<details class="raw-trace" id="raw-trace" hidden>' in body
    disclosure = body.split('id="raw-trace"', 1)[1].split("</details>", 1)[0]
    # Its own label: "Technical details" means only the administrator stop
    # details a non-administrator never receives (test_workspace_default_repair).
    assert "What each step recorded" in disclosure
    assert "Technical details" not in disclosure
    # The page no longer parses raw tool lines into the step list itself.
    assert "TOOL_LINE" not in body and "humanTool" not in body
    assert "e.step && typeof e.step === 'object'" in body
