"""Exact human-review guards checked only inside a native vote reservation."""
from __future__ import annotations

from dataclasses import asdict

from .approval_cards import digest


def approval_review_identity(approval) -> str:
    material = asdict(approval)
    for key in ("status", "decided_at", "decided_by"):
        material.pop(key, None)
    return digest(material)


def channel_vote_review(world, approval, *, status: str, actor: str, binding: str | None) -> dict:
    """Bind a channel's original row to the existing transaction-local guard.

    This captures no permissions, acknowledgement or quorum authority. Normal
    quorum progression remains native; changed material, owner, claim and undo
    round are checked by ``require_locked_vote_review`` under its reservation.
    """
    from .channel_approvals import ChannelApprovalRefused

    content_owner = approval.requested_by or ""
    if approval.goal_id:
        goal = world.get_goal(approval.goal_id)
        if goal is None:
            raise ChannelApprovalRefused("stale_card", "The request's original task is unavailable. Review its current status before deciding.")
        content_owner = goal.owner or ""
    return {"actor": actor, "approval_id": approval.id, "status": status,
            "identity": approval_review_identity(approval), "state": None,
            "event_id": world.approval_audit_event_id(approval.id, status, actor),
            "content_owner": content_owner, "binding": binding}


def require_locked_vote_review(approval, review: dict, *, status: str, actor: str,
                               event_id: str, approvers: list[str], audit_pending: int,
                               content_owner: str | None) -> None:
    """Check the decrypted row/time/round before any vote or outbox write.

    The caller must hold SQLite's write reservation or the Postgres approval
    row lock and pass quorum data read in that same transaction. This guard
    confers no role, employee-content or settings authority.
    """
    from .channel_approvals import ChannelApprovalRefused, require_current_card

    state = None if approval is None else {
        "status": approval.status, "approvals_required": max(1, int(approval.approvals_required or 1)),
        "approved_count": len(approvers), "approvers": approvers,
        "requested_by": approval.requested_by, "audit_pending_count": audit_pending,
        "effective": approval.status != "pending",
    }
    if (approval is None or approval.status != "pending" or not isinstance(review, dict)
            or review.get("actor") != actor or review.get("approval_id") != approval.id
            or review.get("status") != status or review.get("event_id") != event_id
            or review.get("identity") != approval_review_identity(approval)
            or review.get("content_owner") != content_owner
            or (review.get("state") is not None and review["state"] != state)
            or (approval.claimed_by and approval.claimed_by != actor)):
        raise ChannelApprovalRefused(
            "stale_card", "This exact request, review claim or decision round changed. Read its current status and review it again.",
        )
    if status == "approved":
        require_current_card(approval, binding=review.get("binding"))
