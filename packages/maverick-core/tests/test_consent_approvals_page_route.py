""""Ask" reaches a person instead of refusing silently.

A risky step in a task that someone started in Lightwork's chat goes to the
Approvals page and waits for them; nobody deciding in time is still a refusal,
and the request is taken off the page. A headless run with no chat behind it
is refused at once, exactly as before, and the explicit modes are unchanged.
Stopping the task while its step waits withdraws the request, so nothing runs
after Stop.
"""
from __future__ import annotations

import threading
import time

import pytest
from maverick.chat_threads import ChatThreads
from maverick.logging_config import reset_goal_context, set_goal_context
from maverick.world_model import WorldModel

OWNER = "user:sam.lee@northwind.example"


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / ".maverick" / "world.db"
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", path)
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "ask")
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "10")
    monkeypatch.setenv("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS", "0")
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    return path


def _chat_goal(path, owner=OWNER):
    """A task started in Lightwork's chat: its first message is a web turn."""
    world = WorldModel(path=path)
    goal_id = world.create_goal("Archive the three stale drafts", owner=owner)
    threads = ChatThreads(world)
    with threads.store.transaction(f"chat-thread:{goal_id}") as connection:
        threads.record(connection, root_id=goal_id, goal_id=goal_id, owner=owner,
                       text="Archive the three stale drafts")
    assert threads.binding(goal_id) is not None
    world.set_goal_status(goal_id, "active")
    world.close()
    return goal_id


def _headless_goal(path, owner=OWNER):
    world = WorldModel(path=path)
    goal_id = world.create_goal("Nightly clean-up", owner=owner)
    world.set_goal_status(goal_id, "active")
    world.close()
    return goal_id


def _decide_when_parked(path, status, *, by="user:dana.admin@northwind.example"):
    def run():
        world = WorldModel(path=path)
        try:
            for _ in range(200):
                pending = world.pending_approvals()
                if pending:
                    world.decide_approval(pending[0].id, status, decided_by=by)
                    return
                time.sleep(0.05)
        finally:
            world.close()
    thread = threading.Thread(target=run)
    thread.start()
    return thread


def _consent(goal_id, **kwargs):
    from maverick.safety.consent import require_consent

    tokens = set_goal_context(goal_id=goal_id)
    try:
        return require_consent("shell", risk="high", scope="sandbox:/work", **kwargs)
    finally:
        reset_goal_context(tokens)


def _approvals(path):
    world = WorldModel(path=path)
    try:
        return world.list_approvals()
    finally:
        world.close()


def test_ask_sends_a_chat_task_step_to_the_approvals_page_and_runs_once_approved(db):
    goal_id = _chat_goal(db)
    approver = _decide_when_parked(db, "approved")
    decision = _consent(goal_id)
    approver.join(timeout=10)

    assert decision.granted is True
    assert decision.source == "dashboard"
    assert decision.actor == "user:dana.admin@northwind.example"
    (row,) = _approvals(db)
    assert row.goal_id == goal_id
    assert row.requested_by == OWNER


def test_ask_refuses_a_chat_task_step_the_person_rejects(db):
    goal_id = _chat_goal(db)
    denier = _decide_when_parked(db, "denied")
    decision = _consent(goal_id)
    denier.join(timeout=10)

    assert decision.granted is False
    assert decision.source == "dashboard"


def test_nobody_deciding_in_time_refuses_and_takes_the_request_off_the_page(db, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "1")
    goal_id = _chat_goal(db)
    decision = _consent(goal_id)

    assert decision.granted is False
    assert decision.source == "non-tty-deny"
    (row,) = _approvals(db)
    assert row.status == "denied"
    assert row.decided_by == "system:no-decision"


def test_headless_run_with_no_chat_is_refused_at_once_without_a_request(db):
    goal_id = _headless_goal(db)
    started = time.monotonic()
    decision = _consent(goal_id)

    assert decision.granted is False
    assert decision.source == "non-tty-deny"
    assert time.monotonic() - started < 1.0
    assert _approvals(db) == []


def test_ask_outside_any_task_is_refused_at_once(db):
    from maverick.safety.consent import require_consent

    decision = require_consent("shell", risk="high", scope="sandbox:/work")

    assert decision.granted is False
    assert decision.source == "non-tty-deny"
    assert _approvals(db) == []


@pytest.mark.parametrize(("mode", "granted"), [("auto-deny", False), ("auto-approve", True)])
def test_explicit_modes_are_unchanged_for_chat_tasks(db, monkeypatch, mode, granted):
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", mode)
    goal_id = _chat_goal(db)
    decision = _consent(goal_id)

    assert decision.granted is granted
    assert decision.source == "auto"
    assert _approvals(db) == []


def test_ask_at_a_terminal_still_prompts_there(db, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda: "n")
    goal_id = _chat_goal(db)
    decision = _consent(goal_id)

    assert decision.granted is False
    assert decision.source == "prompt"
    assert _approvals(db) == []


def test_stopping_the_task_withdraws_its_waiting_request(db):
    goal_id = _chat_goal(db)

    def stop_when_parked():
        world = WorldModel(path=db)
        try:
            for _ in range(200):
                if world.pending_approvals():
                    world.set_goal_status(goal_id, "cancelled")
                    return
                time.sleep(0.05)
        finally:
            world.close()

    stopper = threading.Thread(target=stop_when_parked)
    stopper.start()
    started = time.monotonic()
    decision = _consent(goal_id)
    stopper.join(timeout=10)

    assert decision.granted is False
    assert decision.source == "task-stopped"
    assert time.monotonic() - started < 5.0
    (row,) = _approvals(db)
    assert row.status == "denied"
    assert row.decided_by == "system:task-stopped"


def test_dashboard_mode_also_stops_waiting_once_the_task_is_stopped(db, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "dashboard")
    goal_id = _headless_goal(db)

    def stop_when_parked():
        world = WorldModel(path=db)
        try:
            for _ in range(200):
                if world.pending_approvals():
                    world.set_goal_status(goal_id, "cancelled")
                    return
                time.sleep(0.05)
        finally:
            world.close()

    stopper = threading.Thread(target=stop_when_parked)
    stopper.start()
    decision = _consent(goal_id)
    stopper.join(timeout=10)

    assert decision.granted is False
    assert decision.source == "task-stopped"


def _withdraw(path, approval_id):
    from maverick.safety.consent import _withdraw_approval

    world = WorldModel(path=path)
    try:
        _withdraw_approval(world, approval_id, "system:task-stopped")
        return world.get_approval(approval_id)
    finally:
        world.close()


def test_withdrawing_an_approval_whose_decision_was_undone_still_denies_it(db):
    world = WorldModel(path=db)
    approval_id = world.create_approval("shell", risk="high", undoable=True)
    event = world.decide_approval_audited(approval_id, "approved", decided_by="user:dana.admin@northwind.example")
    assert world.mark_approval_audit_delivered(event.event_id)
    assert world.undo_approval_decision(approval_id, undone_by="user:dana.admin@northwind.example",
                                        within_seconds=60) == "undone"
    assert world.get_approval(approval_id).status == "pending"
    world.close()

    row = _withdraw(db, approval_id)

    assert row.status == "denied"
    assert row.decided_by == "system:task-stopped"


def test_withdrawing_a_two_person_approval_with_one_audited_vote_denies_it(db):
    world = WorldModel(path=db)
    approval_id = world.create_approval("shell", risk="high", approvals_required=2,
                                        requested_by="user:sam.lee@northwind.example")
    event = world.decide_approval_audited(approval_id, "approved", decided_by="user:dana.admin@northwind.example")
    assert world.mark_approval_audit_delivered(event.event_id)
    assert world.get_approval(approval_id).status == "pending"
    world.close()

    row = _withdraw(db, approval_id)

    assert row.status == "denied"
    assert row.decided_by == "system:task-stopped"
