"""Bind live workflow execution to a validated immutable graph bundle."""
from __future__ import annotations

from dataclasses import dataclass, replace

from . import store
from .ir import Flow


@dataclass(frozen=True)
class ExecutionPlan:
    """Graph identity and execution authority recorded on a durable run."""

    flow: Flow
    definition_digest: str = ""
    release_digest: str = ""
    release_id: str = ""
    definition_version: int = 0
    definition_revision: str = ""
    subflow_digests: dict[str, str | None] | None = None
    execution_channel: str = ""
    execution_user_id: str = ""
    allowed_suites: list[str] | None = None
    pinned: bool = False


def bind_execution_plan(
    flow: Flow, *, prior: store.FlowRun | None, placeholder: store.FlowRun | None,
) -> ExecutionPlan:
    """Restore a saved bundle and validate identity/owners before any effect.

    Resume admission has already restored the prior graph. A queued fresh run
    restores its own graph here. New graphs are captured only after approval
    checks, via :func:`pin_new_plan`.
    """
    checkpoint = prior if prior is not None else placeholder
    if placeholder is not None and placeholder.definition_digest:
        flow = store.load_flow_snapshot(placeholder.definition_digest)
    pinned = bool(checkpoint is not None and checkpoint.definition_digest)
    subflow_digests = dict(checkpoint.subflow_digests) if pinned else {}
    if pinned:
        if flow.id != checkpoint.flow_id:
            raise store.FlowSnapshotError("flow snapshot identity does not match the durable run")
        store.validate_snapshot_bundle_owners(flow, subflow_digests)
    errors = flow.validate()
    if errors:
        raise ValueError("invalid flow execution plan: " + "; ".join(errors))
    return ExecutionPlan(
        flow=flow,
        definition_digest=checkpoint.definition_digest if pinned else "",
        release_digest=checkpoint.release_digest if pinned else "",
        release_id=checkpoint.release_id if pinned else "",
        definition_version=checkpoint.definition_version if pinned else 0,
        definition_revision=(checkpoint.definition_revision or flow.revision) if pinned else "",
        subflow_digests=subflow_digests,
        execution_channel=checkpoint.execution_channel if checkpoint is not None else "",
        execution_user_id=checkpoint.execution_user_id if checkpoint is not None else "",
        allowed_suites=(list(checkpoint.allowed_suites)
                        if checkpoint is not None and checkpoint.allowed_suites is not None else None),
        pinned=pinned,
    )


def pin_new_plan(plan: ExecutionPlan) -> ExecutionPlan:
    """Capture a validated new graph after any required approval checks."""
    if plan.pinned:
        return plan
    digest, version, children = store.snapshot_flow_bundle(plan.flow)
    release = store.release_digest_for(digest, children)
    return replace(plan, definition_digest=digest, definition_version=version,
                   definition_revision=plan.flow.revision, subflow_digests=children,
                   release_digest=release, release_id=release, pinned=True)
