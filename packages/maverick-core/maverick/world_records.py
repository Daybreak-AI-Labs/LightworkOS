"""Domain records shared by world-store adapters. SQL and tenancy remain backend-owned."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Goal:
    id: int
    parent_id: int | None
    title: str
    description: str | None
    status: str
    created_at: float
    updated_at: float
    deadline: float | None
    result: str | None
    owner: str = ""
    execution_principal: str = ""
    domain: str = ""
    project_id: int | None = None
    completed_at: float | None = None


@dataclass
class Question:
    id: int
    goal_id: int | None
    question: str
    asked_at: float
    answer: str | None
    answered_at: float | None


@dataclass
class Approval:
    id: int
    action: str
    risk: str
    scope: str | None
    detail: str | None
    provenance: str | None
    status: str
    requested_at: float
    decided_at: float | None
    claimed_by: str | None = None
    claimed_at: float | None = None
    decided_by: str | None = None
    approvals_required: int = 1
    requested_by: str | None = None
    goal_id: int | None = None
    department: str = ""
    # "open" while a waiting task holds the decision for undo, "settled" once
    # it acted; None for every request whose consumer acts at once.
    undo_hold: str | None = None


@dataclass(frozen=True)
class ApprovalAuditEvent:
    """One transactionally queued human-approval audit event.

    ``final_status`` is populated by the vote that reaches quorum (or by a
    denial).  It is deliberately not applied to ``approvals.status`` until all
    queued events for that approval have a non-null ``delivered_at``.
    """

    event_id: str
    approval_id: int
    status: str
    decided_by: str
    final_status: str | None
    created_at: float
    delivered_at: float | None

    def matches(self, approval_id: int, status: str, decided_by: str) -> bool:
        """Whether this row is the exact vote represented by its stable id."""
        return (
            self.approval_id == int(approval_id)
            and self.status == status
            and self.decided_by == (decided_by or "").strip()
        )


@dataclass
class EpisodeSpend:
    id: int
    goal_id: int
    started_at: float
    ended_at: float | None
    outcome: str | None
    cost_dollars: float
    input_tokens: int
    output_tokens: int
    tool_calls: int
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


@dataclass
class GoalEvent:
    id: int
    goal_id: int
    agent: str
    kind: str
    content: str
    ts: float


@dataclass
class Conversation:
    id: int
    channel: str
    user_id: str
    created_at: float
    last_seen: float


@dataclass
class Turn:
    id: int
    conversation_id: int
    goal_id: int | None
    role: str
    content: str
    ts: float


@dataclass
class Attachment:
    id: int
    goal_id: int
    filename: str
    mime: str
    size_bytes: int
    sha256: str
    path: str
    created_at: float


@dataclass
class FactVersion:
    """One historical value of a fact (see :meth:`WorldModel.fact_history`).

    ``valid_to is None`` marks the value that is still current. The window is
    transaction time: ``valid_from`` is when the value became current and
    ``valid_to`` is when it was superseded or deleted."""
    value: str | None
    valid_from: float
    valid_to: float | None
    source: str = ""
    trust_tier: int = 3
    sensitivity: str = "internal"


Goal.__module__ = "maverick.world_model"
Question.__module__ = "maverick.world_model"
Approval.__module__ = "maverick.world_model"
ApprovalAuditEvent.__module__ = "maverick.world_model"
EpisodeSpend.__module__ = "maverick.world_model"
GoalEvent.__module__ = "maverick.world_model"
Conversation.__module__ = "maverick.world_model"
Turn.__module__ = "maverick.world_model"
Attachment.__module__ = "maverick.world_model"
FactVersion.__module__ = "maverick.world_model"
