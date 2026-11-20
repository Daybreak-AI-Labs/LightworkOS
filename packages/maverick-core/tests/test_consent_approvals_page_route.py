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
    assert decision.source == "no-decision"  # asked, and nobody answered in time
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


def test_a_restart_withdraws_the_requests_its_dead_tasks_were_waiting_on(db):
    # Seen live: the dashboard restarted while a task waited on a shell
    # approval. Recovery marked the task stopped, but its request stayed on the
    # Approvals page as pending with nothing left to act on a decision.
    world = WorldModel(path=db)
    dead, live = _headless_goal(db), _headless_goal(db)
    for goal_id in (dead, live):
        world.set_goal_status(goal_id, "active")

    def park(goal_id, *, undoable):
        tokens = set_goal_context(goal_id=goal_id)
        try:
            return world.create_approval("shell: grep BAT long-report.txt", risk="high",
                                         undoable=undoable)
        finally:
            reset_goal_context(tokens)

    waited_on = park(dead, undoable=True)       # held by a consent wait
    queued_action = park(dead, undoable=False)  # its consumer acts later, not a waiter
    still_live = park(live, undoable=True)
    with world._writing() as conn:  # the dead task stopped heartbeating
        conn.execute("UPDATE goals SET updated_at = 0, heartbeat_at = 0 WHERE id = ?", (dead,))

    assert world.reclaim_orphan_goals(statuses=("active",), resolved_window_seconds=60) == 1
    withdrawn = world.get_approval(waited_on)
    assert (withdrawn.status, withdrawn.decided_by) == ("denied", "system:task-stopped")
    assert world.get_approval(queued_action).status == "pending"
    assert world.get_approval(still_live).status == "pending"
    world.close()


def _command_card(command):
    from maverick.approval_cards import build_approval_card

    return build_approval_card(
        action="shell", summary="Run a command in the sandbox.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"command": command, "timeout_seconds": None},
        parameter_summary=["Runs this exact command once; nothing else is approved."],
        actor=OWNER, workspace="local", role="admin", authority_versions={},
        input_versions={}, credential_versions={}, budget={"currency": "USD"},
        expires_at=time.time() + 600, known_effects=["The command runs in the sandbox folder."],
        unresolved_assumptions=[], before="The command has not run.",
        after="The command has run once.", irreversible=True, display_command=command)


def _command_consent(goal_id, command):
    from maverick.safety.consent import require_consent

    tokens = set_goal_context(goal_id=goal_id)
    try:
        return require_consent("shell", risk="high", scope="sandbox:/work",
                               approval_card=_command_card(command))
    finally:
        reset_goal_context(tokens)


def test_a_command_a_person_rejected_is_not_asked_about_again_in_that_task(db):
    # Seen live: the person rejected `date`; a helper reported it, and the main
    # agent then asked to run the same `date` again.
    goal_id = _chat_goal(db)
    denier = _decide_when_parked(db, "denied")
    assert _command_consent(goal_id, "date").granted is False
    denier.join(timeout=10)

    started = time.monotonic()
    again = _command_consent(goal_id, "date")
    assert again.granted is False and again.source == "rejected-earlier"
    assert time.monotonic() - started < 2.0
    assert [a.status for a in _approvals(db)] == ["denied"]  # no second request

    # A different command, or the same one in another task, still asks.
    approver = _decide_when_parked(db, "approved")
    assert _command_consent(goal_id, "date -u").granted is True
    approver.join(timeout=10)
    other = _chat_goal(db)
    approver = _decide_when_parked(db, "approved")
    assert _command_consent(other, "date").granted is True
    approver.join(timeout=10)


def test_restart_cleanup_leaves_a_request_whose_task_it_cannot_see(db, monkeypatch):
    # Shared PostgreSQL also lists compatibility rows with no workspace; a task
    # this scope cannot read is not proof that the task ended.
    from maverick.safety.consent import withdraw_requests_of_ended_tasks

    world = WorldModel(path=db)
    goal_id = _headless_goal(db)
    tokens = set_goal_context(goal_id=goal_id)
    try:
        approval = world.create_approval("shell: date", risk="high", undoable=True)
    finally:
        reset_goal_context(tokens)
    monkeypatch.setattr(world, "get_goal", lambda _goal_id: None)
    assert withdraw_requests_of_ended_tasks(world) == 0
    assert world.get_approval(approval).status == "pending"
    world.close()


def test_a_refusal_raised_to_the_tool_says_a_person_answered(db):
    # The tool only sees ConsentDenied; it must know a person said no, not
    # that nobody answered in time.
    from maverick.safety.consent import PERSON_REFUSALS, ConsentDenied, require_consent

    goal_id = _chat_goal(db)
    denier = _decide_when_parked(db, "denied")
    tokens = set_goal_context(goal_id=goal_id)
    try:
        with pytest.raises(ConsentDenied) as refused:
            require_consent("shell", risk="high", scope="sandbox:/work", raise_on_deny=True,
                            approval_card=_command_card("uname -a"))
        with pytest.raises(ConsentDenied) as again:
            require_consent("shell", risk="high", scope="sandbox:/work", raise_on_deny=True,
                            approval_card=_command_card("uname -a"))
    finally:
        reset_goal_context(tokens)
    denier.join(timeout=10)
    assert refused.value.source == "dashboard" and refused.value.source in PERSON_REFUSALS
    assert again.value.source == "rejected-earlier" and again.value.source in PERSON_REFUSALS


def test_a_team_task_a_person_started_waits_on_the_approvals_page(db, tmp_path, monkeypatch):
    # Seen live: a team agent started from the Agent teams page asked to run a
    # command and was refused at once ("nobody approved it in time") although
    # nobody was asked. The person who owns the team follows that task like a
    # chat task, so its step waits on the Approvals page.
    from maverick import fleet

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    team = fleet.Fleet(name="Finance-desk", owner=OWNER,
                       agents=(fleet.FleetAgent(name="reconciler", role="operator"),))
    fleet.save_fleet(team, tenant=None)
    world = WorldModel(path=db)
    goal_id = world.create_goal("Run date", "", owner=OWNER,
                                execution_principal=team.principal_for("reconciler"))
    world.set_goal_status(goal_id, "active")
    world.close()
    fleet.record_run("Finance-desk", "reconciler", goal_id, tenant=None)
    approver = _decide_when_parked(db, "approved")
    decision = _command_consent(goal_id, "date")
    approver.join(timeout=10)
    assert decision.granted is True and decision.source == "dashboard"

    # A run with no person behind it is refused without a request, and says so.
    headless = _headless_goal(db)
    refused = _command_consent(headless, "date")
    assert refused.granted is False and refused.source == "non-tty-deny"
    assert len(_approvals(db)) == 1


def test_a_request_nobody_answers_in_time_is_a_timeout_not_a_refusal(db, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "1")
    goal_id = _chat_goal(db)
    decision = _command_consent(goal_id, "date")
    assert decision.granted is False and decision.source == "no-decision"
    (row,) = _approvals(db)
    assert (row.status, row.decided_by) == ("denied", "system:no-decision")
