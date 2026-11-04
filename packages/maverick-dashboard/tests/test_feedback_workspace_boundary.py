"""Human verdicts must follow the current workspace and exact goal owner."""
from __future__ import annotations

import json

import pytest
from maverick import paths
from maverick_dashboard import goal_feedback_store as feedback
from starlette.requests import Request


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr("maverick.config.dashboard_overrides_path", lambda: tmp_path / "dashboard.toml")


def test_colliding_goal_ids_never_read_another_workspace():
    with paths.tenant_scope(tenant="feedback-alpha"):
        feedback.record(7, "alice", "down", value=0, note="Alpha private verdict")
    with paths.tenant_scope(tenant="feedback-beta"):
        assert feedback.latest_for_goal(7, owner="alice") is None
        assert feedback.count() == 0
        feedback.record(7, "alice", "up", value=1, note="Beta verdict")
    with paths.tenant_scope(tenant="feedback-alpha"):
        assert feedback.latest_for_goal(7, owner="alice")["note"] == "Alpha private verdict"
        assert feedback.count(owner="alice") == 1


def test_ambiguous_deployment_legacy_rows_are_not_adopted(tmp_path):
    (tmp_path / "goal-feedback.ndjson").write_text(json.dumps({
        "goal_id": 7, "owner": "alice", "note": "Unknown original workspace",
    }) + "\n", encoding="utf-8")
    with paths.tenant_scope(tenant="feedback-alpha"):
        assert feedback.latest_for_goal(7, owner="alice") is None
        assert feedback.count() == 0


def test_current_owner_lineage_is_required_for_readback():
    with paths.tenant_scope(tenant="feedback-alpha"):
        feedback.record(7, "previous-owner", "down", value=0, note="Previous owner's note")
        assert feedback.latest_for_goal(7, owner="current-owner") is None
        assert feedback.count(owner="current-owner") == 0
        feedback.record(7, "current-owner", "up", value=1, note="Current owner's note")
        assert feedback.latest_for_goal(7, owner="current-owner")["note"] == "Current owner's note"
        assert feedback.latest_for_goal(7, owner="previous-owner")["note"] == "Previous owner's note"


def test_native_goal_read_and_aggregate_pass_trusted_owner(tmp_path, monkeypatch):
    from maverick.world_model import WorldModel
    from maverick_dashboard import _shared, api

    world = WorldModel(tmp_path / "world.db")
    try:
        goal_id = world.create_goal("Owned local task", "", owner="")
        monkeypatch.setattr(api, "_world", lambda: world)
        monkeypatch.setattr(_shared, "_world", lambda: world)
        request = Request({"type": "http", "method": "GET", "headers": [], "path": "/", "query_string": b""})
        with paths.tenant_scope(tenant="feedback-alpha"):
            feedback.record(goal_id, "someone-else", "down", value=0, note="Private previous lineage")
            # The read is a private, uncached response; its body is what matters.
            assert json.loads(api.get_feedback(request, goal_id).body) == {"feedback": None}
            assert api.get_flywheel_state(request)["signal"]["human_feedback"] == 0
            feedback.record(goal_id, "", "up", value=1, note="Local current lineage")
            assert json.loads(api.get_feedback(request, goal_id).body)["feedback"]["note"] == "Local current lineage"
            assert api.get_flywheel_state(request)["signal"]["human_feedback"] == 1
    finally:
        world.close()
