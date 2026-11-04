"""Build immutable human approval context for a paused workflow run."""
from __future__ import annotations

import time
from dataclasses import dataclass

from .ir import Flow
from .run_state import STATUS_PAUSED_APPROVAL, FlowRunResult


@dataclass(frozen=True)
class ApprovalPauseContext:
    flow: Flow
    result: FlowRunResult
    owner: str
    execution_user_id: str
    execution_channel: str
    allowed_suites: list[str] | None
    definition_digest: str
    release_digest: str
    release_id: str
    definition_revision: str
    run_budget_limit: float | None
    cost_dollars: float


def build_human_pause(context: ApprovalPauseContext) -> dict:
    """Capture the reviewed continuation, authority, and data at pause time."""
    flow = context.flow
    res = context.result
    owner = context.owner
    execution_user_id = context.execution_user_id
    execution_channel = context.execution_channel
    allowed_suites = context.allowed_suites
    definition_digest = context.definition_digest
    release_digest = context.release_digest
    release_id = context.release_id
    definition_revision = context.definition_revision
    run_budget_limit = context.run_budget_limit
    # Snapshot the paused human task's declared UI (choices/form/assignee) onto
    # the run, like `prompt` -- the viewer must render what the node said AT
    # PAUSE time, not whatever the flow definition says by the time a human looks.
    human: dict = {}
    if res.status == STATUS_PAUSED_APPROVAL and res.cursor:
        paused_node = flow.node(res.cursor)
        if paused_node is not None:
            from ..approval_cards import build_approval_card, digest
            from .approvals import approval_card_presentation, current_flow_runtime_authority

            next_node = flow.node(paused_node.next) if paused_node.next else None
            continuation = next_node.to_dict() if next_node is not None else {
                "kind": "complete", "id": "end",
            }
            presentation = approval_card_presentation(
                flow, paused_node, next_node, res.prompt,
            )
            expiry = (
                float(res.resume_at)
                if res.resume_at is not None
                else time.time() + 7 * 24 * 3600
            )
            from .payloads import SCHEMA as data_format
            from .payloads import approval_data

            persisted_data = approval_data(res.data or {})
            runtime_authority = current_flow_runtime_authority(
                owner=str(owner or ""),
                execution_user_id=str(execution_user_id or ""),
                execution_channel=str(execution_channel or ""),
                allowed_suites=allowed_suites,
            )
            approval_card = build_approval_card(
                action="flow.resume",
                summary=res.prompt or f"Resume {flow.name or flow.id}",
                target_label=presentation["target_label"],
                target={
                    "flow_id": flow.id,
                    "pause_node": paused_node.id,
                    "continuation": continuation,
                },
                parameters={"data": persisted_data, "continuation": continuation},
                parameter_summary=presentation["parameter_summary"],
                actor=owner or "local:operator",
                workspace=runtime_authority["workspace"],
                role=runtime_authority["role"],
                authority_versions={
                    "definition_digest": definition_digest,
                    "release_digest": release_digest,
                    "release_id": release_id,
                    "execution_principal_sha256": digest(
                        execution_user_id or owner or "local:operator"
                    ),
                    "allowed_suites_sha256": digest(allowed_suites),
                    "runtime_authority_sha256": runtime_authority[
                        "authority_sha256"
                    ],
                },
                input_versions={
                    "run_data_format": data_format,
                    "run_data_sha256": digest(persisted_data),
                    "definition_revision": definition_revision or flow.revision,
                },
                credential_versions={
                    "execution_channel": execution_channel or "local",
                    "inventory_sha256": runtime_authority[
                        "credential_inventory_sha256"
                    ],
                },
                budget={
                    "currency": "USD",
                    "run_limit_dollars": run_budget_limit or "configured runtime limit",
                    "reserved_so_far_dollars": round(context.cost_dollars, 4),
                    "authority_sha256": runtime_authority[
                        "budget_authority_sha256"
                    ],
                },
                expires_at=expiry,
                known_effects=presentation["known_effects"],
                unresolved_assumptions=presentation["unresolved_assumptions"],
                before=presentation["before"],
                after=presentation["after"],
                irreversible=bool(next_node is not None and next_node.kind == "action"),
            )
            human = {"choices": list(paused_node.choices),
                     "assignee": paused_node.assignee,
                     "form": [dict(f) for f in paused_node.form],
                     "approval_card": approval_card}
    return human
