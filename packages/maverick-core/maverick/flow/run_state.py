"""Stable workflow status values and execution result contract."""
from __future__ import annotations

from dataclasses import dataclass, field

# Run statuses ----------------------------------------------------------------
STATUS_QUEUED = "queued"
STATUS_CLAIMED = "claimed"
STATUS_RUNNING = "running"
STATUS_RESUMING = "resuming"
STATUS_COMPLETED = "completed"
STATUS_PAUSED_APPROVAL = "paused_approval"
STATUS_PAUSED_DELAY = "paused_delay"
STATUS_PAUSED_EVENT = "paused_event"
STATUS_REJECTED = "rejected"
STATUS_FAILED = "failed"
STATUS_INDETERMINATE = "indeterminate"
STATUS_BUDGET_LIMITED = "budget_limited"

# The single source of truth for "which statuses mean a run is parked and
# resumable" and "which statuses mean a run is still in flight". Every gate that
# used to hand-list these literals (the resume/retry endpoints, the sweep, the
# JS overlay) should consume these instead -- a new pause status is then added
# in one place, not six.
PAUSED_STATUSES = frozenset({
    STATUS_PAUSED_APPROVAL, STATUS_PAUSED_DELAY, STATUS_PAUSED_EVENT,
})
ACTIVE_STATUSES = frozenset({
    STATUS_QUEUED, STATUS_CLAIMED, STATUS_RUNNING, STATUS_RESUMING,
}) | PAUSED_STATUSES
# A quarantined run may have committed an external side effect, but no reliable
# acknowledgement reached the engine.  It is deliberately neither active nor
# retryable: an operator must reconcile the external system before choosing a
# compensating or replacement action.
QUARANTINED_STATUSES = frozenset({STATUS_INDETERMINATE})


@dataclass
class FlowRunResult:
    status: str
    data: dict = field(default_factory=dict)
    cursor: str | None = None       # node paused/rejected at (for resume)
    resume_at: float | None = None  # epoch for a delay pause
    prompt: str = ""                # approval prompt for the UI
    error: str = ""
    continuation: dict = field(default_factory=dict)
