"""Polling projections can be exercised without constructing the dashboard app."""
from __future__ import annotations

from maverick.world_model import WorldModel
from maverick_dashboard.goal_event_pages import goal_event_page, goal_summary


def test_event_page_drains_before_marking_terminal(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    try:
        goal_id = world.create_goal("Review", "")
        for n in range(3):
            world.append_event(goal_id, "reviewer", "finding", f"finding {n}")
        world.set_goal_status(goal_id, "done")
        goal = world.get_goal(goal_id)

        first = goal_event_page(world, goal, since=0, limit=2)
        assert first.has_more and not first.terminal
        assert [event.content for event in first.events] == ["finding 0", "finding 1"]

        final = goal_event_page(world, goal, since=first.next_id, limit=2)
        assert not final.has_more and final.terminal
        assert [event.content for event in final.events] == ["finding 2"]
        assert final.next_id == final.events[-1].id
    finally:
        world.close()


def test_waiting_question_keeps_blocked_goal_open(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    try:
        goal_id = world.create_goal("Review", "")
        question_id = world.ask("Which document?", goal_id=goal_id)
        world.set_goal_status(goal_id, "blocked")
        page = goal_event_page(world, world.get_goal(goal_id), since=-1, limit=20)
        summary = goal_summary(world, world.get_goal(goal_id), limits={"max_dollars": 2.0})

        assert page.reason_code == "awaiting_input"
        assert page.needs_input and not page.terminal
        assert page.open_question_ids == [question_id]
        assert page.next_id == 0
        assert summary.reason_code == page.reason_code
        assert summary.needs_input and summary.open_question_ids == page.open_question_ids
        assert summary.limits == {"max_dollars": 2.0}
    finally:
        world.close()
