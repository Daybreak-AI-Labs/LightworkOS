"""Board projections work with explicit data and never broaden an owner scope."""
from __future__ import annotations

from maverick.world_model import WorldModel
from maverick_dashboard import board_data


def test_overview_and_spend_project_only_the_requested_owner(tmp_path):
    with WorldModel(tmp_path / "world.db") as world:
        alice = world.create_goal("Alice task", owner="user:alice")
        bob = world.create_goal("Bob task", owner="user:bob")
        world.end_episode(world.start_episode(alice), "ok", "success", cost_dollars=1.25)
        world.end_episode(world.start_episode(bob), "ok", "success", cost_dollars=9.0)
        world.set_goal_status(alice, "done")
        world.set_goal_status(bob, "done")

        overview = board_data._board_overview(world, "user:alice", 30)
        spend = board_data._board_spend(world, "user:alice", 30)

    assert overview["totals"]["total"] == 1
    assert [goal["title"] for goal in overview["recent"]] == ["Alice task"]
    assert spend["totals"]["runs"] == 1
    assert spend["totals"]["dollars"] == 1.25
    assert spend["by_platform"] == []


def test_workspace_projection_uses_the_supplied_department_types(monkeypatch):
    from maverick import assessment

    monkeypatch.setattr(assessment, "custom_template_records", lambda: {
        "privacy_custom": {"department": "privacy"},
        "finance_custom": {"department": "finance"},
    })
    monkeypatch.setattr(assessment, "list_saved", lambda: [
        {"type": "privacy_standard", "status": "approved", "residual_risk": "low"},
        {"type": "privacy_custom", "status": "pending_review", "residual_risk": "high"},
        {"type": "finance_custom", "status": "approved", "residual_risk": "low"},
    ])

    board = board_data._board_workspace("privacy", base={"privacy_standard"})

    assert board["kpis"]["total"] == 2
    assert board["kpis"]["approved"] == 1
    assert board["kpis"]["open"] == 1
    assert board["risk"]["high"] == 1
