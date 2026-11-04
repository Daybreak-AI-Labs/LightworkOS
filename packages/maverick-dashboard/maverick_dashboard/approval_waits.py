"""What a running task is waiting on, for the person following it.

When a risky step is parked on the Approvals page, the task's chat page says
so -- who can decide it, by when, and where -- instead of "Working through
the steps...". Reading it needs access to the task itself; it reveals nothing
beyond the request's id, its deadline and who may decide.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

router = APIRouter()
_LIMIT = 5


def _viewer(request: Request) -> str:
    from .auth import caller_principal

    return caller_principal(request) or ""


def _decide_by(approval) -> float | None:
    """The earlier of the card's expiry and the end of the task's wait."""
    from maverick.approval_cards import ApprovalCardError, decode_approval_detail
    from maverick.safety.consent import dashboard_wait_seconds

    deadlines = []
    try:
        card = decode_approval_detail(approval.detail)
    except ApprovalCardError:
        card = None
    if card is not None:
        deadlines.append(float(card["expires_at"]))
    requested_at = getattr(approval, "requested_at", None)
    if isinstance(requested_at, (int, float)) and not isinstance(requested_at, bool):
        deadlines.append(float(requested_at) + dashboard_wait_seconds())
    return min(deadlines) if deadlines else None


def _who(request: Request, world, approval) -> tuple[str, int]:
    """``(who, remaining)``: "you" or "approver" for one approval needed,
    "more" (yours can count) or "others" when several people must agree, or
    when the person who asked must leave it to someone else."""
    from .approval_decisions import own_request_note
    from .auth import has_permission
    from .content_access import can_read_approval

    required = max(1, int(getattr(approval, "approvals_required", 1) or 1))
    state = world.approval_state(approval.id) or {}
    approvers = list(state.get("approvers") or [])
    remaining = max(1, required - len(approvers))
    viewer = _viewer(request)
    if own_request_note(world, approval, viewer):
        return "others", remaining
    can_decide = (viewer not in approvers and has_permission(request, "operate")
                  and can_read_approval(request, approval, world))
    if required <= 1:
        return ("you" if can_decide else "approver"), remaining
    return ("more" if can_decide else "others"), remaining


@router.get("/api/v1/goals/{goal_id}/approval-wait")
def goal_approval_wait(request: Request, goal_id: int) -> dict:
    """The requests on the Approvals page this task is waiting on."""
    from maverick.attachment_submissions import SubmissionStore

    from ._shared import _world
    from .auth import assert_goal_access, require_permission

    require_permission(request, "view")
    world = _world()
    goal = world.get_goal(goal_id)
    if goal is None:
        raise HTTPException(status_code=404, detail="This task is unavailable.")
    assert_goal_access(request, goal)
    store = SubmissionStore(world)
    scope, values = ("1=1", ()) if store.sqlite else store.scope("tenant_id")
    rows = world.query(
        "SELECT id FROM approvals WHERE status='pending' AND goal_id=? "
        f"AND {scope} ORDER BY id LIMIT {_LIMIT}",
        (int(goal_id), *values),
    )
    waiting = []
    for row in rows:
        approval = world.get_approval(int(row[0]))
        if approval is None or approval.status != "pending" or approval.goal_id != goal_id:
            continue
        who, remaining = _who(request, world, approval)
        waiting.append({
            "id": approval.id,
            "who": who,
            "remaining": remaining,
            "decide_by": _decide_by(approval),
            "href": f"/approvals#approval-{approval.id}",
        })
    return {"waiting": waiting}


__all__ = ["router"]
