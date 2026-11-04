# Goal dispatch and execution ownership

`maverick.runner.start_goal_observed` and `start_goal_observed_async` submit a
goal once and return a `DispatchObservation`. The observation describes what the submission adapter
reported. It does not grant authority to execute, cancel, or settle a goal.
The caller must still use the same tenant and principal authorization as the
entry point and consult the durable goal owner for the current state.

- `queued` means the queue adapter returned from enqueue. Its `receipt_id` is
  the authenticated message identifier, not a worker lease, a proof of
  completion, or a cancellation capability.
- `reported` preserves a status returned by the adapter. A local synchronous
  dispatch normally returns after its execution finishes, but custom adapters
  can report other states; the string itself must be interpreted in context.
- `not_accepted` means this invocation was rejected before dispatch. It does
  not prove that an earlier or concurrent invocation was not accepted, so it
  does not itself authorize a pending goal to be marked blocked.
- `unknown` means the adapter cannot establish the submission outcome. Its
  compatibility status may be `None` or `error`; neither proves that
  submission or any side effect failed. A raised transport error can likewise
  occur after a remote owner accepted the request; callers must reconcile
  before retrying.

The existing `run_goal_in_background` and `Dispatcher.submit` interfaces keep
their string-or-`None` return values for compatibility. Local and queue
dispatchers also expose `submit_observed`; older and third-party dispatchers
are adapted without inventing a receipt. The gRPC adapter distinguishes local
preflight rejection from an unknown RPC result; a timeout or a missing status
does not establish whether the remote worker accepted the goal. Queue enqueue
errors likewise retain the signed message identity as an unknown observation,
because the broker may have stored it before its acknowledgement was lost.
An adapter observation must agree with its compatibility status: for example,
an unknown outcome cannot be presented as `queued` or `done`. Invalid reports
raise at the synchronous boundary and become `unknown` in the async wrapper.

`start_goal_handle` and `start_goal_handle_async` expose the same single
submission as an `ExecutionHandle`; an existing observation can also be wrapped
with `as_handle()` without submitting again. Local, queue, and gRPC adapters
offer `submit_handle()` directly. The handle retains the observation, owner,
goal ID and any available receipt. It is an immutable submission-time snapshot,
not a live status query, a durable record, or an authorization credential.
Unexpected submission exceptions yield an `unknown` observation and are never
automatically retried. The queue retains a signed message identifier when it
has one, including after an acknowledgement loss; gRPC has no equivalent
receipt in its existing wire contract.

For each of these adapters, `handle.cancel()` and `handle.settle()` return an
`ExecutionControlResult` with outcome `unsupported` and `performed=False`.
They do not send an operation to a worker or broker. The result says only that
the handle did not perform that control operation; it does not say whether
execution started, stopped, or was settled by its owner. Reconciliation and
operator actions still require the appropriate tenant-scoped owner interface.

Cancelling an async waiter does not stop a submission already running in the
executor or cancel an accepted job. The existing local job queue can delete a
pending job through its own operator boundary, but this is not exposed as a
general goal cancellation operation: worker claim races, tenant authorization,
and a broker's ownership need their own guarantees. Once a worker claims a
job, the worker owns its lease and completion/failure settlement. Per-goal
budget and quota settlement remain with the execution lifecycle. Do not treat a
queue receipt, a Python task cancellation, or an unknown result as evidence that
either cancellation or settlement occurred.
