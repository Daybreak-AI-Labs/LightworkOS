"""Every personal alert says why, what is needed and by when, and opens the thing.

NOT-1: each category carries a reason label, the action needed with its due
time (an approval's real expiry; a question's wait), and a link that lands on
the exact item. No private content travels with it: never result text or a
question, and an approval or flow alert never repeats its card.
"""
from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest
from maverick import budget_guidance
from maverick_dashboard import flow_approval_inbox
from maverick_dashboard import personal_notifications_api as api

PRIVATE = ("PRIVATE RESULT", "PRIVATE QUESTION", "PRIVATE CARD")


def _goal(goal_id, status, *, result=None, deadline=None, domain="finance_ap"):
    return SimpleNamespace(id=goal_id, owner="user:alice", title=f"Task {goal_id}", status=status,
                           result=result, deadline=deadline, project_id=None, completed_at=None,
                           domain=domain)


def _projection(monkeypatch, goals, *, questions=None, approvals=(), states=None, flows=None,
                budget=None):
    world = SimpleNamespace(
        personal_alert_goals=lambda actor, **kw: [] if kw["after_id"] else goals,
        open_questions=lambda goal_id: (questions or {}).get(goal_id, []),
        list_projects=lambda **_: [], get_project=lambda _id: None,
        pending_approvals=lambda: list(approvals),
        approval_state=lambda approval_id: (states or {}).get(approval_id))
    monkeypatch.setattr(api.auth, "can_access_goal", lambda *_: True)
    monkeypatch.setattr(api.auth, "has_permission", lambda *_: True)
    monkeypatch.setattr(api.auth, "caller_suites", lambda *_: None)
    monkeypatch.setattr(flow_approval_inbox, "pending_for_request",
                        lambda _request: {"items": flows or [], "coverage": "current"})
    monkeypatch.setattr(budget_guidance, "warning_sources", lambda _actor: list(budget or []))
    sources, _tasks, _projects, _partial = api._projection(object(), "user:alice", world=world)
    return {source["ref"]: source for source in sources}


def _assert_explained(source):
    assert source["reason"] and source["action"], source
    assert source["due_at"] is not None or source["no_due"], source
    assert source["due_label"], source
    assert source["href"].startswith("/") and not source["href"].startswith("//")
    text = json.dumps(source)
    for secret in PRIVATE:
        assert secret not in text, (secret, source)


@pytest.mark.parametrize("status,label,action", [
    ("done", "Finished", "Review the result"),
    ("failed", "Did not finish", "Open the task to see why it stopped, then run it again"),
    ("blocked", "Needs attention", "Open the task to see what it needs"),
])
def test_task_state_alerts_say_you_started_it_what_to_do_and_open_the_task(monkeypatch, status, label, action):
    sources = _projection(monkeypatch, [(_goal(1, status, result="PRIVATE RESULT"), 1, 0)])
    state = sources["goal:1:state"]
    _assert_explained(state)
    assert state["label"] == label and state["action"] == action
    assert state["reason"] == "You started this task"
    assert state["href"] == "/chat/goal/1"
    assert state["agent"] == "finance_ap"  # "Mute alerts from this agent" can name it


def test_changed_result_alert_asks_for_a_review_without_the_result(monkeypatch):
    sources = _projection(monkeypatch, [(_goal(2, "done", result="PRIVATE RESULT"), 1, 1)])
    changed = sources["goal:2:result"]
    _assert_explained(changed)
    assert changed["action"] == "Review the updated result"
    assert changed["href"] == "/chat/goal/2"


def test_question_alert_opens_the_answer_box_and_says_the_task_waits(monkeypatch):
    asked = time.time() - 600
    question = SimpleNamespace(id=7, goal_id=3, question="PRIVATE QUESTION?", asked_at=asked,
                               answer=None, answered_at=None)
    sources = _projection(monkeypatch, [(_goal(3, "blocked"), 1, 0)], questions={3: [question]})
    alert = sources["goal:3:question:7"]
    _assert_explained(alert)
    assert alert["label"] == "Needs your answer"
    assert alert["action"] == "Answer the agent's question so the task can continue"
    assert alert["due_at"] is None and alert["no_due"] == "The task waits until you answer"
    assert alert["waiting_since"] == asked
    assert alert["href"] == "/chat/goal/3#question-panel"


def test_deadline_alert_carries_the_real_deadline(monkeypatch):
    deadline = time.time() + 1800
    sources = _projection(monkeypatch, [(_goal(4, "active", deadline=deadline), 1, 0)])
    alert = sources["goal:4:deadline"]
    _assert_explained(alert)
    assert alert["due_at"] == deadline and alert["due_label"] == "Due"
    assert alert["action"] == "Finish the task or change its deadline"


def test_assigned_approval_alert_uses_the_cards_real_expiry_and_opens_that_card(monkeypatch):
    from maverick import approval_cards

    expires = time.time() + 3600
    monkeypatch.setattr(approval_cards, "decode_approval_detail",
                        lambda detail: {"expires_at": expires, "summary": "PRIVATE CARD"})
    approval = SimpleNamespace(id=12, claimed_by="user:alice", department="", requested_by="user:bob",
                               requested_at=10.0, detail="lw-approval-card:...", action="shell")
    sources = _projection(monkeypatch, [], approvals=[approval],
                          states={12: {"status": "pending", "approvers": []}})
    alert = sources["approval:12"]
    _assert_explained(alert)
    assert alert["reason"] == "You were assigned to decide this request"
    assert alert["action"] == "Approve or reject the request"
    assert alert["due_at"] == expires and alert["due_label"] == "Decide by"
    assert alert["href"] == "/approvals#approval-12"


def test_legacy_approval_without_a_card_says_no_expiry_instead_of_inventing_one(monkeypatch):
    approval = SimpleNamespace(id=13, claimed_by="user:alice", department="", requested_by="user:bob",
                               requested_at=10.0, detail="plain legacy detail", action="shell")
    sources = _projection(monkeypatch, [], approvals=[approval],
                          states={13: {"status": "pending", "approvers": []}})
    alert = sources["approval:13"]
    _assert_explained(alert)
    assert alert["due_at"] is None and alert["no_due"] == "No expiry is set"


@pytest.mark.parametrize("owner,reason", [
    ("user:alice", "You started this flow run"),
    ("user:bob", "You are the assigned reviewer for this flow step"),
])
def test_flow_approval_alert_names_why_and_the_cards_expiry(monkeypatch, owner, reason):
    expires = time.time() + 7200
    row = {"run_id": "r1", "flow_id": "f1", "owner": owner, "assignee": "user:alice",
           "href": "/flows/f1/runs/r1?approval_review=1", "approval_card_status": "current",
           "approval_binding_sha256": "a" * 64, "due_at": None,
           "approval_card": {"expires_at": expires, "summary": "PRIVATE CARD"}}
    sources = _projection(monkeypatch, [], flows=[row])
    alert = sources["flow-approval:r1"]
    _assert_explained(alert)
    assert alert["reason"] == reason and alert["due_at"] == expires
    assert alert["href"] == "/flows/f1/runs/r1?approval_review=1"


def test_budget_warning_alert_says_why_and_what_to_review(monkeypatch):
    from datetime import datetime, timezone

    today = datetime.now(timezone.utc).date().isoformat()
    rows = [{"id": "PBW-1", "principal": "user:alice", "day": today, "dimension": "monthly",
             "threshold": 0.8}]
    monkeypatch.setattr(budget_guidance, "policy", lambda: {"warnings": True, "guidance": True})
    monkeypatch.setattr(budget_guidance, "_warnings_store",
                        lambda: SimpleNamespace(list=lambda limit: rows))
    [warning] = budget_guidance.warning_sources("user:alice")
    sources = _projection(monkeypatch, [], budget=[warning])
    alert = sources["PBW-1"]
    _assert_explained(alert)
    assert alert["reason"] == "Your spending allowance crossed a warning level"
    assert alert["action"] == "Review the work scheduled against your allowance"
    assert alert["href"] == "/budget"


def test_a_new_alert_kind_still_says_why_what_and_by_when(monkeypatch):
    """Another stream's source (for example an approval reminder) gets the
    category's wording instead of arriving bare."""
    reminder = {"ref": "reminder:1", "version": "1", "category": "needs-decision", "goal_id": None,
                "project_id": None, "title": "Approval reminder", "label": "Still waiting",
                "href": "/approvals#approval-1"}
    sources = _projection(monkeypatch, [], budget=[reminder])
    _assert_explained(sources["reminder:1"])
