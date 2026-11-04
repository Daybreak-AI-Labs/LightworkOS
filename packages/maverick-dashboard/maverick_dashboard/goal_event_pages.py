"""Build durable goal-event polling responses from an authorized goal."""
from __future__ import annotations

from maverick.stop_reasons import stop_payload

from ._event_stream import TERMINAL_RUN_STATUSES, event_page, event_payload, replay_cursor
from .api_schemas import GoalEventOut, GoalEventsResponse, GoalOut
from .goal_waiting import open_question_ids
from .plain_labels import risk_label


def goal_reason_code(goal, open_ids: list[int]) -> str | None:
    """One stable cause across task details and event polling."""
    if open_ids:
        return "awaiting_input"
    stop = stop_payload(goal.status, goal.result)
    return stop["kind"] if stop else None


def goal_summary(world, goal, *, limits: dict | None = None) -> GoalOut:
    """Project an already-authorized goal with its current waiting state."""
    open_ids = open_question_ids(world, goal)
    risk = risk_label(goal) or {}
    return GoalOut(
        id=goal.id,
        status=goal.status,
        title=goal.title,
        description=goal.description,
        result=goal.result,
        limits=limits,
        reason_code=goal_reason_code(goal, open_ids),
        risk_tier=risk.get("tier"),
        risk_reasons=risk.get("reasons"),
        needs_input=bool(open_ids),
        open_question_ids=open_ids,
        created_at=goal.created_at,
        updated_at=goal.updated_at,
    )


def goal_event_page(world, goal, *, since: int, limit: int) -> GoalEventsResponse:
    """Project one page; callers are responsible for authorizing the goal."""
    since = replay_cursor(since)
    events, has_more = event_page(world, goal.id, since, limit)
    open_ids = open_question_ids(world, goal)
    stop = stop_payload(goal.status, goal.result)
    return GoalEventsResponse(
        status=goal.status,
        result=stop["message"] if stop else goal.result,
        reason_code=goal_reason_code(goal, open_ids),
        stop=stop,
        next_id=events[-1].id if events else since,
        events=[GoalEventOut(**event_payload(event)) for event in events],
        has_more=has_more,
        terminal=goal.status in TERMINAL_RUN_STATUSES and not has_more and not open_ids,
        needs_input=bool(open_ids),
        open_question_ids=open_ids,
    )
