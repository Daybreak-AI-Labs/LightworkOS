"""A task waiting on the Approvals page says who decides and by when."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from maverick.logging_config import reset_goal_context, set_goal_context

_ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture
def env(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick.world_model import WorldModel

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "300")
    world = WorldModel(tmp_path / "world.db")
    from maverick_dashboard.app import app

    yield TestClient(app, base_url="http://127.0.0.1", headers=_ORIGIN), world
    world.close()


def _park(world, goal_id, *, required=1, requested_by=None, ttl=600.0):
    from maverick.approval_cards import build_approval_card, encode_approval_detail

    card = build_approval_card(
        action="shell", summary="Run one command in the sandbox.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"command": "ls"},
        parameter_summary=["Runs the command once."], actor=requested_by or "local:operator",
        workspace="local", role="operator", authority_versions={}, input_versions={},
        credential_versions={}, budget={}, expires_at=time.time() + ttl,
        known_effects=["Runs one command."], unresolved_assumptions=[],
        before="Not run.", after="Run once.", irreversible=True,
    )
    tokens = set_goal_context(goal_id=goal_id)
    try:
        return world.create_approval("shell", risk="high", scope="sandbox:/work",
                                     detail=encode_approval_detail(card),
                                     approvals_required=required, requested_by=requested_by)
    finally:
        reset_goal_context(tokens)


def test_a_task_with_nothing_waiting_says_nothing(env):
    client, world = env
    goal_id = world.create_goal("Archive drafts")
    response = client.get(f"/api/v1/goals/{goal_id}/approval-wait")
    assert response.status_code == 200
    assert response.json() == {"waiting": []}


def test_the_person_who_can_decide_is_told_it_is_their_approval(env):
    client, world = env
    goal_id = world.create_goal("Archive drafts")
    approval_id = _park(world, goal_id)
    other_goal = world.create_goal("Something else")
    _park(world, other_goal)

    (item,) = client.get(f"/api/v1/goals/{goal_id}/approval-wait").json()["waiting"]
    assert item["id"] == approval_id
    assert item["who"] == "you"
    assert item["href"] == f"/approvals#approval-{approval_id}"
    # The task gives up after the configured wait, so that is the deadline
    # even though the card itself would allow longer.
    requested_at = world.get_approval(approval_id).requested_at
    assert item["decide_by"] == pytest.approx(requested_at + 300, abs=1)


def test_the_card_expiry_is_the_deadline_when_it_comes_first(env):
    client, world = env
    goal_id = world.create_goal("Archive drafts")
    approval_id = _park(world, goal_id, ttl=60)
    (item,) = client.get(f"/api/v1/goals/{goal_id}/approval-wait").json()["waiting"]
    assert item["id"] == approval_id
    assert item["decide_by"] < world.get_approval(approval_id).requested_at + 120


def test_a_decided_request_is_no_longer_waiting(env):
    client, world = env
    goal_id = world.create_goal("Archive drafts")
    approval_id = _park(world, goal_id)
    world.decide_approval(approval_id, "denied", decided_by="system:no-decision")
    assert client.get(f"/api/v1/goals/{goal_id}/approval-wait").json() == {"waiting": []}


def test_a_requester_who_cannot_count_is_told_other_people_decide(env, monkeypatch):
    client, world = env
    from maverick_dashboard import approval_waits

    goal_id = world.create_goal("Wire the payment")
    _park(world, goal_id, required=2, requested_by="user:sam")
    monkeypatch.setattr(approval_waits, "_viewer", lambda request: "user:sam")
    monkeypatch.setattr("maverick.safety.dual_control.allow_self_approval", lambda: False)

    (item,) = client.get(f"/api/v1/goals/{goal_id}/approval-wait").json()["waiting"]
    assert item["who"] == "others"
    assert item["remaining"] == 2


def test_an_unknown_task_is_not_found(env):
    client, _world = env
    assert client.get("/api/v1/goals/4242/approval-wait").status_code == 404
