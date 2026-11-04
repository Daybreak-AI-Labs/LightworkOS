"""Thumbs-down takes an optional reason, says where feedback goes, and administrators see a per-agent summary."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import goal_feedback_store as feedback
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture
def world(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr("maverick.config.dashboard_overrides_path", lambda: tmp_path / "dashboard.toml")
    w = world_model.WorldModel(tmp_path / "world.db")
    yield w
    w.close()


def _done(world, title="Which POs are overdue?", domain="proc_po_chaser"):
    gid = world.create_goal(title, "", domain=domain)
    episode = world.start_episode(gid)
    world.end_episode(episode, "Three are overdue.", "success")
    world.set_goal_status(gid, "done", result="Three are overdue.")
    return gid


def _rate(gid, body):
    review = client.get(f"/api/v1/goals/{gid}/answer-feedback").json()
    from uuid import uuid4
    return client.post(f"/api/v1/goals/{gid}/feedback", json={**body, "revision": review["revision"],
        "expected_context": review["context"], "operation_id": uuid4().hex})


def test_a_reason_and_comment_are_stored_with_the_agent(world):
    gid = _done(world)
    r = _rate(gid, {"rating": "down", "reason": "incomplete", "note": "It skipped the Fabrikam POs."})
    assert r.status_code == 200, r.text
    row = client.get(f"/api/v1/goals/{gid}/feedback").json()["feedback"]
    assert (row["rating"], row["reason"]) == ("down", "incomplete")
    assert row["note"] == "It skipped the Fabrikam POs."


def test_an_unknown_reason_is_refused(world):
    gid = _done(world)
    r = _rate(gid, {"rating": "down", "reason": "<script>"})
    assert r.status_code == 422


@pytest.mark.parametrize(("enabled", "expected"), [
    (True, "Thanks. Saved with this task and recorded as a learning signal. "
           "Your workspace's learning policy decides how it is used to improve this specialist."),
    (False, "Thanks. Saved with this task. It was not recorded as a learning signal, "
            "so it does not change this specialist."),
])
def test_the_acknowledgement_says_plainly_where_feedback_goes(world, monkeypatch, enabled, expected):
    from maverick import result_feedback_receipts

    monkeypatch.setattr(result_feedback_receipts, "observe", lambda *args, **kwargs: enabled)
    gid = _done(world)
    body = _rate(gid, {"rating": "up"}).json()
    assert body["acknowledgement"] == expected
    with_reason = _rate(gid, {"rating": "down", "reason": "wrong"}).json()["acknowledgement"]
    assert with_reason.endswith("The administrators' summary shows counts and the reasons picked "
                                "for this specialist, not what you wrote.")
    # A customer-built agent (or the general assistant) is an agent, not a specialist.
    custom = _done(world, domain="acme_invoice_helper")
    text = _rate(custom, {"rating": "up"}).json()["acknowledgement"]
    assert text.endswith("this agent.") and "specialist" not in text


def test_the_third_rejection_of_the_same_agent_asks_one_short_question(world):
    goals = [_done(world, f"Question {n}") for n in range(4)]
    asks = []
    for gid in goals[:3]:
        body = _rate(gid, {"rating": "down"}).json()
        asks.append(body.get("follow_up"))
    assert asks[:2] == [None, None]
    assert asks[2] == {"question": "What would make this better?"}
    # Adding a reason to a rejection already counted does not ask again.
    again = _rate(goals[2], {"rating": "down", "reason": "wrong"}).json()
    assert again.get("follow_up") is None
    # Neither does a fourth rejection: the question is asked once.
    assert _rate(goals[3], {"rating": "down"}).json().get("follow_up") is None


def test_rejections_of_different_agents_do_not_add_up(world):
    goals = [_done(world, "a", "proc_po_chaser"), _done(world, "b", "legal_nda_desk"), _done(world, "c", "")]
    for gid in goals:
        assert _rate(gid, {"rating": "down"}).json().get("follow_up") is None


def test_the_admin_summary_counts_ratings_and_reasons_per_agent_without_comments():
    feedback.record(1, "user:a", "down", value=0, reason="wrong", note="Private comment", agent="proc_po_chaser")
    feedback.record(2, "user:b", "down", value=0, reason="incomplete", agent="proc_po_chaser")
    feedback.record(3, "user:c", "up", value=1, agent="proc_po_chaser")
    feedback.record(2, "user:b", "up", value=1, agent="proc_po_chaser")  # the latest verdict wins
    feedback.record(4, "user:a", "down", value=0, reason="too_long", agent="")
    rows = {row["agent"]: row for row in feedback.summary_by_agent()}
    chaser = rows["proc_po_chaser"]
    assert (chaser["up"], chaser["down"]) == (2, 1)
    assert chaser["reasons"] == [{"reason": "wrong", "label": "Wrong or inaccurate", "count": 1}]
    assert [item["label"] for item in chaser["recent"]] == ["Wrong or inaccurate"]
    assert rows[""]["reasons"][0]["label"] == "Too long"
    assert "Private comment" not in repr(rows)


def test_administrators_see_the_summary_on_the_learning_page(world):
    feedback.record(1, "user:a", "down", value=0, reason="wrong", note="Private comment", agent="proc_po_chaser")
    body = client.get("/learning").text
    section = body.split('id="agent-feedback"', 1)[1].split("</section>", 1)[0]
    assert "PO Confirmation Chaser" in section and "Wrong or inaccurate" in section
    assert "Private comment" not in section
    assert "What people said about each agent and specialist" in body


def test_the_learning_page_stays_closed_to_people_who_are_not_administrators(world, monkeypatch):
    from maverick_dashboard import rbac

    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    monkeypatch.setattr("maverick_dashboard.auth.caller_principal", lambda request: "user:operator")
    monkeypatch.setattr("maverick_dashboard.auth._authorization_principal", lambda request: "user:operator")
    rbac.set_role("user:operator", "operator")
    r = client.get("/learning", follow_redirects=False)
    assert r.status_code in (303, 403)
