# Run accounting and recovery

The in-app Billing page includes an owner-filtered usage reconciliation trail.
It shows cumulative counters, acknowledged legacy credits, and retained daily
increments for each durable receipt, with pagination. Receipt lookup failures
remain visible. These internal quota counters are separate from episode-based
statements and provider invoices; they cannot reconstruct unreported provider
usage after an interruption.

`run_goal` owns the lifecycle boundary for the existing goal and episode
records. Completion, waiting for input, Shield refusal, budget exhaustion,
setup/provider exceptions, and asyncio or dashboard cancellation close any
started episode. Final episode spend and quota settlement happen after paid
finalization work. The in-run outcome branches stage the episode result;
the outer boundary persists its final spend once and always attempts quota
settlement and trace-context cleanup.

Execution completion (`goal.status = done`) does not confer human acceptance,
validation of an external effect, or permission to release a deliverable.
Existing review, signoff, and external-action records remain authoritative for
those decisions. A model answer is never a human approval.

## Durable resumption

Durable execution remains opt-in (`MAVERICK_DURABLE=1` or `[durable] enabled`).
Its supported boundary remains the existing linear depth-zero agent loop,
using the SQLite world model's `checkpoints` table. Swarm-tree and in-flight
external-action checkpointing are not supported.

Resumption restores counters and elapsed execution time into the caller's
existing `Budget`. Current caps, capability, execution principal, tenant
reservation, and resource owner are not imported from history. The existing
execution-principal binding and current tenant/quota checks run first. For
the standard orchestrator checkpoint, restored caps are checked before any
briefing/planning call; root discovery also covers domain-agent keys, and the
root agent's own restoration is idempotent.
An explicitly selected episode must belong to the requested goal.

Existing accounting plus checkpoint history is conserved. A successful quota
write annotates the existing checkpoint budget JSON with `_settled` counters.
On a subsequent invocation with a fresh Budget, cumulative episode totals
include historical usage, while the quota ledger receives only the usage
not already acknowledged. Failed quota writes retain unsettled counters for
recovery and retain the existing conservative tenant reservation behavior.
Historical token, dollar, tool, and elapsed counters must be finite,
nonnegative and complete. Corrupt or unavailable requested resume history
blocks execution instead of silently starting over. A missing checkpoint
still permits the existing warm restart. Optional inspection APIs keep their
best-effort defaults.

Checkpoints survive interrupted and blocked results. They are removed only
after successful run finalization. No released world-model migration changes;
the additional accounting field is optional JSON in the existing checkpoint
budget column. Older valid snapshots remain readable and count their saved
usage as unsettled because they carry no ledger acknowledgement.

## Limits and reconciliation

The quota ledger and SQLite checkpoint are separate stores. Durable runs now
establish an opaque, principal-bound settlement identity in the world database
before execution. The usage ledger atomically stores cumulative counters and
their receipt in one versioned JSON document. A repeated or older delivery
cannot add the same usage twice; only an increase is charged to the current
UTC day. Resume reconciles its budget against the receipt before any paid
continuation, including usage recorded after the last message checkpoint.
An episode with an existing receipt and no resumable checkpoint cannot resume:
its receipt does not contain tool counts, elapsed time, or execution state.
Starting a new episode gives fresh work a distinct accounting identity without
overwriting the old episode's usage.

Existing unversioned ledgers remain readable and migrate on the first durable
settlement. Existing billing and quota readers keep their original daily-total
view. Ordinary retention deletes expired daily totals and receipt charge dates;
minimal cumulative receipts remain to prevent charging old restored checkpoints
again. A full tenant-state deletion removes those receipts as well. Do not
roll back to an older binary after ledger migration: older readers cannot
interpret the new envelope. Restore a consistent pre-upgrade state snapshot
when performing a code rollback.

Legacy checkpoints with an acknowledged marker import that credit once.
Historical unacknowledged legacy usage still requires operator reconciliation:
no migration can infer a missing receipt. A hard process loss can also lose
usage since the last persisted boundary; provider receipts remain necessary
for reconciling unreturned or uncheckpointed usage. The settlement boundary
does not establish live provider invoice accuracy or recover usage that was
never recorded.

Resuming messages does not undo tools or establish whether a timed-out
external mutation succeeded. The governed external-action operation and
reconciliation records, rather than an agent retry, must resolve that state.

Required Shield policy blocks absent or unavailable input/output scans,
including a detector verdict carrying `scan_error`. Intentionally optional
Shield installations retain the existing warned fail-open behavior. Rendered
code diffs retain their pre-existing scan exemption. A final prose refusal
persists only the refusal, closes the episode as blocked, and preserves the
existing prohibition on exporting the rejected final through success webhooks.

## Offline verification

`python3 -m pytest -q packages/maverick-core/tests/test_run_lifecycle_reliability.py`
covers the lifecycle and accounting boundaries with synthetic provider
responses, isolated SQLite records, the real local usage ledger, and no live
external mutations. The durable-checkpoint, orchestrator, output/webhook,
quota and tenant-budget suites provide compatibility coverage.
