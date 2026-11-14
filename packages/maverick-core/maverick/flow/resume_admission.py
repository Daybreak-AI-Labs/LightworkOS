"""Prepare a durable workflow resume before claiming or executing effects."""
from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass

from . import store
from .approval_resume import prepare_approval_decision
from .ir import Flow, FlowNode, _contains_high_risk, _is_high_risk_action
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


RETRY_NEEDS_APPROVAL = (
    "This run stopped at a step that needed approval, and that step itself failed. "
    "Retrying would send it again without a new review. Start a new run so a "
    "person can review it again."
)


def _failed_leaves(flow: Flow, frame: object, depth: int = 0) -> list[FlowNode] | None:
    """The innermost nodes a saved failure frame was executing, or None if unknown.

    Each nested frame names its own graph (``flow_id``) and cursor; a finished
    concurrent branch has no cursor and contributes nothing.
    """
    if depth > 32 or not isinstance(frame, dict):
        return None
    node = flow.node(frame.get("cursor"))
    if node is None:
        return None
    children = frame.get("children") or {}
    if not isinstance(children, dict):
        return None
    if not children:
        return [node]
    graphs = ([node.body] if node.body is not None else []) + list(node.branches)
    leaves: list[FlowNode] = []
    for child in children.values():
        if not isinstance(child, dict):
            return None
        if "cursor" in child and child["cursor"] is None:
            continue
        matches = [graph for graph in graphs if graph.id == child.get("flow_id")]
        if not matches:
            return None
        for graph in matches:
            found = _failed_leaves(graph, child, depth + 1)
            if found is None:
                return None
            leaves.extend(found)
    return leaves


def retry_approval_refusal(flow: Flow, prior: store.FlowRun) -> str:
    """Why a retry from failure would reuse an approval, or "" when it would not.

    Every high-risk action sits behind an approval that admitted one dispatch.
    A retry carries no decision, so it must not re-send a high-risk action that
    itself failed.  A hold before dispatch (a budget limit) or a failure of other
    work inside a gated container resumes where it stopped, without repeating
    completed items.  A budget hold is judged the same way: a concurrent branch
    may have stopped at its own failed high-risk action while another was held.
    """
    node = flow.node(prior.cursor) if prior.cursor else None
    if node is None:
        return ""
    continuation = prior.continuation if isinstance(prior.continuation, dict) else {}
    leaves = _failed_leaves(flow, continuation.get("frame")) if continuation else None
    if leaves is None:
        # No usable invocation history: judge the whole step, failing closed.
        risky = _is_high_risk_action(node) or any(
            _contains_high_risk(graph)
            for graph in ([node.body] if node.body is not None else []) + list(node.branches)
        )
    else:
        risky = any(_is_high_risk_action(leaf) for leaf in leaves)
    return RETRY_NEEDS_APPROVAL if risky else ""


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
        refusal = retry_approval_refusal(flow, prior)
        if refusal:
            raise not_resumable(refusal)
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
