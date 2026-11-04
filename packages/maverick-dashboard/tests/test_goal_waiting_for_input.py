"""A goal parked on a question is 'blocked' but not finished.

Reporting every blocked goal the same way -- ``terminal: true`` with nothing
saying whether the task is waiting for a person's answer or has stopped for
good -- would make an integration that trusts ``terminal`` stop polling a task
that only needs an answer. The REST API states waiting-for-input from the
question queue itself, and the timestamps a client needs are on the goal.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated_world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    yield


def _world(tmp_path):
    from maverick import world_model
    return world_model.WorldModel(tmp_path / "world.db")


def _parked(tmp_path, *questions):
    """A goal the agent parked with ``ask_user``: blocked, no result, questions open."""
    w = _world(tmp_path)
    gid = w.create_goal("plan the launch", "")
    w.set_goal_status(gid, "blocked")
    qids = [w.ask(q, goal_id=gid) for q in questions]
    return w, gid, qids


def test_a_goal_parked_on_a_question_says_it_needs_input(tmp_path):
    _, gid, (first, second) = _parked(tmp_path, "Which market first?", "What is the budget?")

    body = client.get(f"/api/v1/goals/{gid}").json()

    assert body["status"] == "blocked"
    assert body["reason_code"] == "awaiting_input"
    assert body["needs_input"] is True
    assert body["open_question_ids"] == [first, second]


def test_a_goal_blocked_for_another_reason_does_not_claim_to_need_input(tmp_path):
    w = _world(tmp_path)
    gid = w.create_goal("plan the launch", "")
    w.set_goal_status(gid, "blocked", result="internal error")

    body = client.get(f"/api/v1/goals/{gid}").json()

    assert body["status"] == "blocked"
    assert body["reason_code"] == "internal_error"
    assert body["needs_input"] is False
    assert body["open_question_ids"] == []


def test_answered_questions_no_longer_count(tmp_path):
    w, gid, (first, second) = _parked(tmp_path, "Which market first?", "What is the budget?")
    w.answer(first, "US")

    body = client.get(f"/api/v1/goals/{gid}").json()
    assert body["open_question_ids"] == [second] and body["needs_input"] is True

    w.answer(second, "$5k")
    w.set_goal_status(gid, "blocked", result="internal error")
    body = client.get(f"/api/v1/goals/{gid}").json()
    assert body["open_question_ids"] == [] and body["needs_input"] is False


def test_a_running_goal_is_not_reported_as_waiting(tmp_path):
    w = _world(tmp_path)
    gid = w.create_goal("plan the launch", "")
    w.set_goal_status(gid, "active")
    w.ask("Which market first?", goal_id=gid)

    body = client.get(f"/api/v1/goals/{gid}").json()

    assert body["needs_input"] is False and body["open_question_ids"] == []


def test_goal_carries_its_timestamps(tmp_path):
    w = _world(tmp_path)
    gid = w.create_goal("plan the launch", "")
    goal = w.get_goal(gid)

    body = client.get(f"/api/v1/goals/{gid}").json()

    assert body["created_at"] == pytest.approx(goal.created_at)
    assert body["updated_at"] == pytest.approx(goal.updated_at)
    assert body["updated_at"] >= body["created_at"] > 0


def test_the_goal_list_reports_waiting_goals_too(tmp_path):
    _, gid, (qid,) = _parked(tmp_path, "Which market first?")

    rows = client.get("/api/v1/goals").json()

    [row] = [r for r in rows if r["id"] == gid]
    assert row["needs_input"] is True and row["open_question_ids"] == [qid]


def test_each_goal_in_a_page_gets_only_its_own_questions(tmp_path):
    w = _world(tmp_path)
    first = w.create_goal("plan the launch", "")
    second = w.create_goal("book the venue", "")
    other = w.create_goal("send the invoice", "")
    for gid in (first, second, other):
        w.set_goal_status(gid, "blocked")
    q1 = w.ask("Which market first?", goal_id=first)
    q2 = w.ask("Which city?", goal_id=second)
    q3 = w.ask("Which market, again?", goal_id=first)
    w.answer(w.ask("Already settled", goal_id=other), "yes")

    rows = {r["id"]: r for r in client.get("/api/v1/goals").json()}

    assert rows[first]["open_question_ids"] == [q1, q3]
    assert rows[second]["open_question_ids"] == [q2]
    assert rows[other]["open_question_ids"] == [] and rows[other]["needs_input"] is False


def test_events_are_not_terminal_while_the_goal_waits_for_an_answer(tmp_path):
    _, gid, (qid,) = _parked(tmp_path, "Which market first?")

    body = client.get(f"/api/v1/goals/{gid}/events").json()

    assert body["status"] == "blocked"
    assert body["reason_code"] == "awaiting_input"
    assert body["terminal"] is False
    assert body["needs_input"] is True
    assert body["open_question_ids"] == [qid]


@pytest.mark.parametrize("status", ["blocked", "done", "failed", "cancelled"])
def test_events_stay_terminal_when_nothing_is_waiting(tmp_path, status):
    w = _world(tmp_path)
    gid = w.create_goal("plan the launch", "")
    w.set_goal_status(gid, status, result="stopped")

    body = client.get(f"/api/v1/goals/{gid}/events").json()

    assert body["terminal"] is True
    assert body["needs_input"] is False and body["open_question_ids"] == []


def test_a_finished_goal_with_a_stale_question_is_still_terminal(tmp_path):
    w = _world(tmp_path)
    gid = w.create_goal("plan the launch", "")
    w.ask("Which market first?", goal_id=gid)
    w.set_goal_status(gid, "done", result="shipped")

    body = client.get(f"/api/v1/goals/{gid}/events").json()

    assert body["terminal"] is True and body["needs_input"] is False
