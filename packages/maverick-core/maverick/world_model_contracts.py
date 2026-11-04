"""Shared, narrow contracts for world-model goal lookups.

SQLite and PostgreSQL retain their own persistence and record types. The
attributes below are the stable portion consumers can use across both.
Backend-specific fields such as SQLite's completion timestamp are excluded.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable


@runtime_checkable
class GoalRecord(Protocol):
    id: int
    parent_id: int | None
    title: str
    description: str | None
    status: str
    created_at: float
    updated_at: float
    deadline: float | None
    result: str | None
    owner: str
    execution_principal: str
    domain: str
    project_id: int | None


class GoalLookup(Protocol):
    def get_goal(self, goal_id: int) -> GoalRecord | None:
        """Read a goal visible within the backend's tenant boundary."""
        ...


class ConversationRecord(Protocol):
    id: int
    channel: str
    user_id: str
    created_at: float
    last_seen: float


class TurnRecord(Protocol):
    id: int
    conversation_id: int
    goal_id: int | None
    role: str
    content: str
    ts: float


@runtime_checkable
class ConversationStore(Protocol):
    """Conversation operations scoped by the backend's tenant boundary."""

    def get_or_create_conversation(self, channel: str, user_id: str) -> ConversationRecord: ...

    def append_turn(self, conversation_id: int, role: str, content: str,
                    goal_id: int | None = None) -> int: ...

    def recent_turns(self, conversation_id: int, limit: int = 20) -> Sequence[TurnRecord]: ...


class ApprovalRecord(Protocol):
    id: int
    action: str
    risk: str
    status: str
    requested_at: float
    decided_at: float | None
    decided_by: str | None
    approvals_required: int
    requested_by: str | None


@runtime_checkable
class ApprovalStore(Protocol):
    """Approval reads and legacy decisions; audited decisions stay separate."""

    def get_approval(self, approval_id: int) -> ApprovalRecord | None: ...

    def pending_approvals(self) -> Sequence[ApprovalRecord]: ...

    def decide_approval(self, approval_id: int, status: str,
                        decided_by: str | None = None) -> bool: ...


class GoalEventRecord(Protocol):
    id: int
    goal_id: int
    agent: str
    kind: str
    content: str
    ts: float


@runtime_checkable
class GoalEventReader(Protocol):
    """Page goal events within the backend's tenant boundary."""

    def goal_events(self, goal_id: int, since_id: int = 0,
                    limit: int = 200) -> Sequence[GoalEventRecord]: ...


@runtime_checkable
class GoalEventStore(GoalEventReader, Protocol):
    """Append as well as read goal events."""

    def append_event(self, goal_id: int, agent: str, kind: str, content: str) -> int: ...


@runtime_checkable
class FactStore(Protocol):
    """Current facts, including optional revision checks on mutations."""

    def get_fact(self, key: str, *, as_of: float | None = None) -> str | None: ...

    def upsert_fact(self, key: str, value: str, episode_id: int | None = None, *,
                    source: str = "", trust_tier: int = 3, sensitivity: str = "internal",
                    expected_revision: int | None = None, tags: list[str] | None = None) -> int: ...

    def delete_fact(self, key: str, *, expected_revision: int | None = None) -> int: ...

    def list_facts(self, key_prefix: str, limit: int = 50) -> list[tuple[str, int]]: ...
