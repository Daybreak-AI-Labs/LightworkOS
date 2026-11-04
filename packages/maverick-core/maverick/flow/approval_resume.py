"""Validate the human decision supplied for a durable approval pause."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .ir import Flow
from .store import FlowRun


@dataclass(frozen=True)
class ApprovalDecision:
    """Validated decision and binding to check before claiming an effect."""

    actor: str
    binding: str
    expired: bool
    resume_fields: dict


def prepare_approval_decision(
    flow: Flow, prior: FlowRun, *, submitted_inputs: dict,
    decision: str | None, decided_by: str, expired: bool,
    binding: str, expiry_binding: str,
    actor_matches: Callable[[str, str], bool],
) -> ApprovalDecision:
    """Refuse unauthenticated verdicts before changing the saved checkpoint."""
    if expired:
        if decision or decided_by or submitted_inputs:
            raise ValueError("approval expiry payload is invalid")
        return ApprovalDecision("", expiry_binding, True, {"expired": True})

    verdict = str(decision or "").strip()
    paused = flow.node(prior.cursor) if prior.cursor else None
    allowed_verdicts = {"approved", "rejected"}
    if paused is not None:
        allowed_verdicts.update(str(value) for value in paused.choices)
    if flow.recipe_teaching is not None and prior.cursor == "teaching_review":
        # Selecting a continuation is distinct from approving it.
        allowed_verdicts = {"route:0", "route:1", "rejected"}
    if not verdict or verdict not in allowed_verdicts:
        raise ValueError("an explicit valid approval decision is required")
    actor = str(decided_by or "").strip()
    if not actor:
        raise ValueError("an attributable approver identity is required")
    assignee = str(
        (prior.human or {}).get("assignee")
        or (paused.assignee if paused is not None else "")
        or ""
    )
    if not actor_matches(actor, assignee):
        raise ValueError("the approver is not the declared assignee")
    return ApprovalDecision(actor, binding, False, {"decision": verdict})
