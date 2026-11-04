# Recurring job advancement and recovery

The SQLite job queue assigns each new recurring schedule a random `recurrence_id`,
an occurrence number and an immutable `scheduled_at`. A retry changes `run_at` and
the claim attempt, not the schedule occurrence. Two independently enqueued schedules
remain independent even when their cron, timezone and payload are identical.

The queue creates a successor and records the parent's `successor_id` and legacy
`__rearmed__` marker in one transaction. A unique database index also protects the
schedule/occurrence pair. Retries use the stored link even when the successor has
already run, been cancelled or been purged. Mutable handler checkpoints do not
change the schedule template; `start_goal` checkpoints are not copied to future goals.
Cron and timezone calculations use next-future-occurrence behavior.

`JobQueue.set_payload` requires `expected_attempts`. It returns `False` unless
that attempt still owns a running row. Handlers must stop when it returns `False`;
they must not continue business execution after losing their checkpoint lease.
The built-in worker does this. Rearm raises `LeaseLost` for a stale attempt. This
does not make external effects exactly once: an old worker frozen during an
already-started effect can still overlap a reclaimed worker. Effectful handlers
still need idempotency/reconciliation at their external boundary.

## Upgrade

Stop all old worker processes before opening an existing queue with this version;
do not run mixed-version writers. Back up the queue using the existing operational
backup procedure. Schema changes and legacy-row classification occur transactionally.
New columns and indexes are additive. Existing non-recurring rows are unchanged.
Never downgrade while writers are active.

Unattempted recurring rows receive independent schedule identities automatically.
Rows carrying a durable `__rearmed__` marker retain that decision: a missing child
is not silently replaced. Legacy `scheduled_at` uses the retained `run_at`, because
older schemas did not preserve the original timestamp across retry rescheduling.

An attempted legacy occurrence with no rearm marker cannot prove whether its old
worker inserted a successor before crashing. Payload matching cannot distinguish
that child from an independent identical schedule. Such rows become `failed` with
`recurrence_reconcile_required=True` and a payload-free diagnostic. They remain
visible in failed-job counts and are excluded from automatic terminal-row purge.
No business handler is run for them automatically.

## In-product schedule management and recovery

Automations retains a schedule definition while occurrences run, pause, or retire.
Changes compare the displayed revision inside the queue transaction. Pausing stops
new occurrence admission; running work and its existing retries retain their
payload. Changing future runs cancels only unattempted future occurrences, records
why, and creates the next occurrence strictly after the current time. Resume does
not replay missed occurrences. History and definition versions remain visible even
when an active occurrence has left the pending queue.

For a parked recurrence, an administrator chooses **Review recovery**. The review
shows retained queue evidence and explicitly labels the historical external result
unknown. Confirm that old workers are stopped, record the rationale, and either
link the reviewed existing successor or authorize one future occurrence. The
confirmation binds the exact job, attempt, definition and successor evidence plus
the authenticated workspace. Changed evidence refuses the decision. This operation
never reruns the historical business action. **History → Download audit history**
exports definition decisions and retained occurrence states. Ordinary queue
retention still bounds occurrence history; definition versions remain durable.

The direct UI and API use the queue reconciliation transaction. Copilot does not
manage schedules and must not claim that it performed these changes.

## Explicit local operator reconciliation

This recovery API is for an administrator who already has filesystem authority over
the correct tenant's queue database. It is not registered as a model tool or remote
endpoint. An integration exposing it must enforce its own administrator permission;
`confirm=True` records deliberate invocation, not a substitute for authentication.

With old workers stopped, inspect the failed row and successor history in the
correct tenant queue. Avoid copying payloads or credentials into tickets/logs.
Record the job ID, attempt number and the chosen recovery. Use exactly one option:

```python
from pathlib import Path
from maverick.job_queue import JobQueue

queue = JobQueue(Path("/operator-selected/tenant/jobs.db"))
job = queue.get(parent_job_id)
assert job.recurrence_reconcile_required

# Link a reviewed existing successor with matching schedule/authority template.
successor = queue.reconcile_recurrence(
    job.id, expected_attempts=job.attempts,
    successor_id=reviewed_successor_id, confirm=True,
)

# OR, after checking history, explicitly authorize one new FUTURE occurrence.
successor = queue.reconcile_recurrence(
    job.id, expected_attempts=job.attempts, rearm=True, confirm=True,
)
```

Choose one branch, not both. The queue verifies the inspected attempt/state and
compatible linked template, atomically records the decision, and makes identical
retries idempotent. A missing or incompatible successor is refused. An already
linked successor cannot be shared by a second historical parent. The historical
occurrence remains failed with a reconciliation note; this never reruns its
possibly completed business work. Any desired replay of that historical work
requires a separate reviewed execution decision.

After reconciliation, inspect `successor_id`, the future job and the historical
note before restarting workers. Ordinary CLI/dashboard schedule seeding continues
to work without adopting another schedule merely because its payload matches.
