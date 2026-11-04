"""Prepare a durable workflow resume before claiming or executing effects."""
from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass

from . import store
from .approval_resume import prepare_approval_decision
from .ir import Flow
from .resume_inputs import prepare_resume_inputs
from .run_state import STATUS_BUDGET_LIMITED, STATUS_FAILED
from .transitions import ResumeDecision, decide_resume


@dataclass(frozen=True)
class ResumeAdmission:
    """The saved run, pinned graph, and validated user-supplied continuation."""

    prior: store.FlowRun
    flow: Flow
    owner: str
    resume: dict
    submitted_inputs: dict
    approval_resume: bool
    approval_actor: str
    approval_binding: str
    approval_expired: bool


def prepare_saved_resume(
    flow: Flow, *, run_id: str, owner: str, inputs: dict | None,
    from_failure: bool, budget_limit_dollars: float | None,
    decision: str | None, decided_by: str, expired: bool,
    approval_binding: str, expiry_binding: str,
    actor_matches: Callable[[str, str], bool], not_resumable: type[ValueError],
) -> ResumeAdmission:
    """Load and validate a checkpoint without mutating it or invoking a node."""
    prior = store.load_run(run_id)
    if prior is None:
        raise ValueError(f"no such flow run {run_id!r}")
    admission = decide_resume(prior.status, prior.cursor, from_failure=from_failure)
    retry = admission is ResumeDecision.RETRY_FAILURE
    is_approval = admission is ResumeDecision.APPROVAL
    if admission is ResumeDecision.REFUSE:
        raise not_resumable(
            f"run {run_id!r} is not paused (status {prior.status!r})"
            + ("; it has no failure cursor to retry from"
               if from_failure and prior.status == STATUS_FAILED else ""))
    if budget_limit_dollars is not None:
        if (
            prior.status != STATUS_BUDGET_LIMITED or not from_failure
            or isinstance(budget_limit_dollars, bool)
            or not math.isfinite(budget_limit_dollars)
            or budget_limit_dollars <= max(
                prior.cost_dollars, prior.budget_limit_dollars or 0.0,
            )
        ):
            raise not_resumable("a budget-held run requires a larger finite total allowance")
    if prior.definition_digest:
        flow = store.load_flow_snapshot(prior.definition_digest)

    submitted, resume_data = prepare_resume_inputs(flow, prior, inputs)
    resume = {"node_id": prior.cursor, "data": resume_data}
    actor, selected_binding, is_expired = "", "", False
    if retry:
        resume["rerun"] = True
        if prior.continuation:
            resume["continuation"] = prior.continuation
    elif is_approval:
        approval = prepare_approval_decision(
            flow, prior, submitted_inputs=submitted, decision=decision,
            decided_by=decided_by, expired=expired, binding=approval_binding,
            expiry_binding=expiry_binding, actor_matches=actor_matches,
        )
        actor, selected_binding, is_expired = approval.actor, approval.binding, approval.expired
        resume.update(approval.resume_fields)
    return ResumeAdmission(
        prior=prior, flow=flow, owner=owner or prior.owner, resume=resume,
        submitted_inputs=submitted, approval_resume=is_approval,
        approval_actor=actor, approval_binding=selected_binding, approval_expired=is_expired,
    )
