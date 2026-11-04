"""Build an explicit interpreter continuation without running any work node."""
from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass

from .ir import NODE_APPROVAL, Flow, FlowNode
from .run_state import STATUS_FAILED, STATUS_INDETERMINATE, STATUS_REJECTED, FlowRunResult


@dataclass(frozen=True)
class ResumePlan:
    """Execution input and any terminal refusal produced during admission."""

    data: dict
    start: str | None
    frame: dict | None = None
    result: FlowRunResult | None = None


def legacy_cursor_ambiguous(flow: Flow, node: FlowNode, resolve_flow) -> bool:
    """A legacy leaf ID must identify exactly one non-container invocation."""
    pending = [flow]
    visited = set()
    ambiguous = node.kind in {"scope", "foreach", "parallel", "while", "subflow"}
    while pending and not ambiguous:
        candidate = pending.pop()
        if id(candidate) in visited:
            continue
        visited.add(id(candidate))
        for child_node in candidate.nodes.values():
            children = list(child_node.branches or [])
            if child_node.body is not None:
                children.append(child_node.body)
            if child_node.kind == "subflow":
                sub = resolve_flow(child_node.flow_ref) if resolve_flow else None
                if sub is None:
                    ambiguous = True
                    break
                children.append(sub)
            for child in children:
                if child.node(node.id) is not None:
                    ambiguous = True
                pending.append(child)
    return ambiguous


def valid_continuation(resume: dict, continuation: object) -> bool:
    return (isinstance(continuation, dict) and resume.get("rerun") is True
            and continuation.get("version") == 1 and isinstance(continuation.get("frame"), dict))


def _approval_continuation(node: FlowNode, decision, resume: dict,
                           data: dict, start: str | None) -> ResumePlan:
    if resume.get("expired"):
        if node.on_expire is None:
            return ResumePlan(data, None, result=FlowRunResult(
                status=STATUS_REJECTED, data=data, cursor=node.id))
        if node.output:
            data[node.output] = "expired"
        start = node.on_expire
    elif not resume.get("rerun"):
        if decision == "approved" or (decision and decision in node.choices):
            if node.output:
                data[node.output] = decision
        else:
            return ResumePlan(data, None, result=FlowRunResult(
                status=STATUS_REJECTED, data=data, cursor=node.id))
    return ResumePlan(data, start)


def prepare_resume(
    flow: Flow, *, data: dict | None, resume: dict | None, resolve_flow,
    on_node: Callable[[FlowNode, str, float | None], None] | None,
    approval_outcome: Callable[[str], float | None],
) -> ResumePlan:
    """Resolve a pause/retry, retaining fail-closed replay and approval rules."""
    if resume and resume.get("continuation"):
        continuation = copy.deepcopy(resume["continuation"])
        if not valid_continuation(resume, continuation):
            return ResumePlan({}, None, result=FlowRunResult(
                status=STATUS_FAILED, error="unsupported flow continuation"))
        return ResumePlan(dict(data or {}), flow.start, frame=continuation["frame"])

    if not resume:
        return ResumePlan(dict(data or {}), flow.start)

    restored = dict(resume.get("data") or data or {})
    node = flow.node(resume.get("node_id"))
    decision = resume.get("decision")
    if node is not None and (decision in ("approved", "rejected") or decision in node.choices):
        (on_node or (lambda *_: None))(node, decision, approval_outcome(decision))
    if node is None:
        return ResumePlan(restored, None, result=FlowRunResult(
            status=STATUS_FAILED, data=restored, cursor=resume.get("node_id"),
            error=(f"cannot resume: node {resume.get('node_id')!r} no longer "
                   "exists in this flow version")))
    if resume.get("rerun") and legacy_cursor_ambiguous(flow, node, resolve_flow):
        return ResumePlan(restored, None, result=FlowRunResult(
            status=STATUS_INDETERMINATE, data=restored, cursor=node.id,
            error="legacy failure lacks invocation history; reconcile completed work before creating a replacement",
        ))
    if decision == "rejected":
        return ResumePlan(restored, None, result=FlowRunResult(
            status=STATUS_REJECTED, data=restored, cursor=node.id))

    # A pause continues after its node; a failure retry re-enters that node.
    start = node.id if resume.get("rerun") else node.next
    if node.kind == NODE_APPROVAL:
        return _approval_continuation(node, decision, resume, restored, start)
    return ResumePlan(restored, start)
