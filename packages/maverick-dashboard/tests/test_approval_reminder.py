"""A risky step waiting 10 minutes with no decision reminds its approvers once.

The reminder is one in-app alert (the bell) for each person who could decide
the request in Lightwork, through the personal alerts stream H turned on for
approvals waiting; no email, Slack or Teams. The approval card then says
"Reminder sent". Times come from a fake clock: nothing here waits.
"""
from __future__ import annotations

import re
import time

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
SAM = "user:sam.lee@northwind.example"
DANA = "user:dana.admin@northwind.example"
ROLES = {SAM: "operator", DANA: "operator"}


@pytest.fixture
def env(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("")
    for name in ("MAVERICK_SEPARATE_APPROVER", "MAVERICK_CONSENT_DASHBOARD_TIMEOUT",
                 "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = WorldModel(tmp_path / "world.db")
    from maverick_dashboard import auth, rbac, scim_groups
    from maverick_dashboard.app import app

    monkeypatch.setattr(auth, "role_for_principal", lambda p: ROLES.get(p, "operator"))
    monkeypatch.setattr(auth, "global_role_for_principal", lambda p: ROLES.get(p, "operator"))
    monkeypatch.setattr(rbac, "list_users", lambda: dict(ROLES))
    monkeypatch.setattr(scim_groups, "active_for_principal", lambda p: True)
    yield TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN), world
    world.close()
    config.reset_config_cache()


def _config(tmp_path, text):
    from maverick import config

    (tmp_path / "config.toml").write_text(text)
    config.reset_config_cache()


def _approval(world, *, minutes_ago=0.0, owner=SAM, risk="high", expires_in=1800.0, held=True):
    from maverick import world_model
    from maverick.approval_cards import build_approval_card, encode_approval_detail
    from maverick.logging_config import reset_goal_context, set_goal_context

    parked_at = time.time() - minutes_ago * 60
    card = build_approval_card(
        action="shell", summary="Run one command in the sandbox.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"command": "ls"},
        parameter_summary=["Runs the command once."], actor=owner, workspace="local",
        role="operator", authority_versions={}, input_versions={}, credential_versions={},
        budget={}, expires_at=parked_at + expires_in, known_effects=["Runs one command."],
        unresolved_assumptions=[], before="Not run.", after="Run once.", irreversible=True,
    )
    goal_id = world.create_goal("Archive the stale drafts", owner=owner)
    tokens = set_goal_context(goal_id=goal_id)
    real_time = world_model.time.time
    try:
        world_model.time.time = lambda: parked_at
        # Parked by the consent wait, as a task's risky step is (held), or by
        # a requester that acts whenever it is decided.
        approval_id = world.create_approval("shell", risk=risk, scope="sandbox:/work",
                                            detail=encode_approval_detail(card), requested_by=owner,
                                            undoable=held)
    finally:
        world_model.time.time = real_time
        reset_goal_context(tokens)
    return approval_id


def _grant(monkeypatch, world, approval_id, reader):
    from maverick_dashboard import content_access

    resource = content_access.approval_resource(world.get_approval(approval_id), world)
    row = {"id": "ECA-1", "tenant": content_access.tenant(), "requester": reader,
           "owner": resource["owner"], "resource_kind": "approval",
           "resource_id": resource["resource_id"], "resource_revision": resource["resource_revision"],
           "status": "approved", "expires_at": time.time() + 3600, "purpose": "approval_review",
           "reviewed_by": "user:admin"}
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access, "_reviewer_current", lambda grant: True)
    monkeypatch.setattr(content_access.STORE, "list", lambda: [row])


def _as(monkeypatch, principal):
    from maverick_dashboard import api, auth

    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: principal)
    monkeypatch.setattr(api, "_supervisor", lambda request: principal)


def _reminders(world, actor):
    from maverick_dashboard import personal_notifications_api as notifications

    sources, _tasks, _projects, _partial = notifications._projection(None, actor, world=world)
    return [s for s in sources if s["ref"].startswith("approval-reminder:")]


# ------------------------------------------------------------------ the timing

def test_the_reminder_is_due_ten_minutes_after_a_request_waits(env):
    from maverick_dashboard.approval_reminders import reminder_due_at

    _client, world = env
    approval = world.get_approval(_approval(world))
    assert reminder_due_at(approval) == pytest.approx(approval.requested_at + 600)


def test_no_reminder_when_the_wait_ends_first(env, tmp_path):
    from maverick_dashboard.approval_reminders import reminder_due_at

    _client, world = env
    _config(tmp_path, "[approval]\ndashboard_wait_seconds = 300\n")
    assert reminder_due_at(world.get_approval(_approval(world))) is None


def test_no_reminder_once_decided(env):
    from maverick_dashboard.approval_reminders import reminder_due_at

    _client, world = env
    approval_id = _approval(world, minutes_ago=11)
    world.decide_approval(approval_id, "denied", decided_by=SAM)
    assert reminder_due_at(world.get_approval(approval_id)) is None


def test_no_reminder_once_the_wait_has_ended(env, monkeypatch):
    # A dashboard-mode wait that times out leaves the request pending; the
    # task is no longer waiting, so nobody signing in later is reminded and
    # the card does not say a reminder went out about a waiting step.
    from maverick_dashboard import approval_reminders

    _client, world = env
    approval_id = _approval(world)
    _grant(monkeypatch, world, approval_id, DANA)
    approval = world.get_approval(approval_id)
    monkeypatch.setattr(approval_reminders, "_now", lambda: approval.requested_at + 1799)
    assert len(_reminders(world, DANA)) == 1
    assert approval_reminders.reminder_sent(world, approval) is True
    monkeypatch.setattr(approval_reminders, "_now", lambda: approval.requested_at + 1800)
    assert _reminders(world, DANA) == []
    assert approval_reminders.reminder_sent(world, approval) is False


# --------------------------------------------------------- who is reminded

def test_the_people_who_can_decide_are_reminded_once_after_ten_minutes(env, monkeypatch):
    from maverick.personal_notifications import PersonalInbox
    from maverick_dashboard import approval_reminders

    _client, world = env
    approval_id = _approval(world)
    _grant(monkeypatch, world, approval_id, DANA)
    assert _reminders(world, DANA) == []          # minute 0: nothing yet
    requested_at = world.get_approval(approval_id).requested_at
    monkeypatch.setattr(approval_reminders, "_now", lambda: requested_at + 601)
    (reminder,) = _reminders(world, DANA)
    assert reminder["category"] == "needs-decision"
    assert reminder["href"] == f"/approvals#approval-{approval_id}"
    assert reminder["label"] == "Still waiting for a decision"
    # The person who asked must leave it to Dana (separate approver), so the
    # reminder goes to Dana only.
    assert _reminders(world, SAM) == []

    from maverick.personal_notifications import DEFAULTS

    inbox = PersonalInbox(DANA)
    first = inbox.refresh([reminder], dict(DEFAULTS), now=requested_at + 601)
    again = inbox.refresh([reminder], dict(DEFAULTS), now=requested_at + 900)
    assert len(first["items"]) == 1 and len(again["items"]) == 1


def test_a_requester_who_alone_can_decide_is_reminded(env, monkeypatch):
    from maverick_dashboard import approval_reminders

    _client, world = env
    approval_id = _approval(world)
    requested_at = world.get_approval(approval_id).requested_at
    monkeypatch.setattr(approval_reminders, "_now", lambda: requested_at + 601)
    assert [r["ref"] for r in _reminders(world, SAM)] == [f"approval-reminder:{approval_id}"]
    assert _reminders(world, DANA) == []          # Dana can't open Sam's private request


def test_no_reminder_when_in_app_alerts_are_off(env, monkeypatch, tmp_path):
    from maverick_dashboard import approval_reminders

    _client, world = env
    _config(tmp_path, "[notifications]\npersonal_alerts = false\n")
    approval_id = _approval(world)
    requested_at = world.get_approval(approval_id).requested_at
    monkeypatch.setattr(approval_reminders, "_now", lambda: requested_at + 601)
    assert approval_reminders.reminder_sent(world, world.get_approval(approval_id)) is False


# ------------------------------------------------------------------- the card

def test_the_card_says_reminder_sent_after_ten_minutes(env, monkeypatch):
    client, world = env
    fresh = _approval(world)
    waiting = _approval(world, minutes_ago=11)
    _as(monkeypatch, SAM)
    page = client.get("/approvals").text

    def card(approval_id):
        start = re.search(rf'<article class="approval-item"[^>]*data-id="{approval_id}"', page)
        assert start is not None
        rest = page[start.start():]
        return rest[:rest.index("</article>")]

    assert "Reminder sent" in card(waiting)
    assert "Reminder sent" not in card(fresh)


def test_a_request_no_task_waits_on_is_reminded_after_the_consent_wait(env, monkeypatch):
    # An external agent's or data-use request waits until someone decides it;
    # the consent wait's end says nothing about it.
    from maverick_dashboard import approval_reminders

    _client, world = env
    approval_id = _approval(world, held=False, expires_in=86_400)   # a 24-hour card
    _grant(monkeypatch, world, approval_id, DANA)
    approval = world.get_approval(approval_id)
    monkeypatch.setattr(approval_reminders, "_now", lambda: approval.requested_at + 7200)
    assert len(_reminders(world, DANA)) == 1
    assert approval_reminders.reminder_sent(world, approval) is True


@pytest.mark.parametrize("held", [False, True])
def test_no_reminder_once_the_card_has_expired(env, monkeypatch, held):
    # A request nothing waits on stops being remindable when its card expires
    # (approving it is refused from then on). That also covers a task's
    # request parked before the upgrade that added the hold (held=False here),
    # whose card expires shortly after the task's wait.
    from maverick_dashboard import approval_reminders

    _client, world = env
    approval_id = _approval(world, held=held, expires_in=1500)
    _grant(monkeypatch, world, approval_id, DANA)
    approval = world.get_approval(approval_id)
    monkeypatch.setattr(approval_reminders, "_now", lambda: approval.requested_at + 1499)
    assert len(_reminders(world, DANA)) == 1
    monkeypatch.setattr(approval_reminders, "_now", lambda: approval.requested_at + 1500)
    assert _reminders(world, DANA) == []
    assert approval_reminders.reminder_sent(world, approval) is False
