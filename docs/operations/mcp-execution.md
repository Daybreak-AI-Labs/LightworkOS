# MCP execution ownership and cancellation

MCP task cancellation and request cancellation reach an execution-specific
cooperative stop handle. They do not arm the global HALT switch. The handle is
bound through a ContextVar inside the worker, so agent turn/tool boundaries and
the existing guarded async provider wait observe it. Async child tasks and
`asyncio.to_thread` copies inherit it; unrelated callers and later work on a
reused thread do not. Existing global halt checks retain precedence.

Task metadata under `_meta["lightwork/execution"]` distinguishes:

- `cancelRequested`: an owner, expiry, or shutdown requested a stop.
- `cancelAcknowledged`: the owned stop check observed the request.
- `executionFinished`: the actual worker Future finished, including its cleanup.
- `executionStarted`: the runner passed its initial stop check.
- `effectStatus`: `not_started` for work refused before entry, otherwise `unknown`.

This metadata describes execution control, not business reconciliation. In
particular, acknowledgment is neither worker exit nor proof of rollback. A
successful task's normal result remains its result; the execution handle does
not independently prove external effects. Cancellation retains the terminal
`cancelled` task status and discards late results. Capacity remains occupied until
the real worker exits. Queued cancellation never calls `Future.cancel()` to
pretend that an executor's queued item has drained. The global and stable
principal task quotas still count these records.

Both transports await task results with an async completion signal, preserving
fresh authorization checks after the wait. A cancelled waiting request removes
only its waiter; it does not cancel the detached task. Result waiters are capped
at the store's maximum task count. The synchronous `TaskStore.result()` API
remains available for embeddings and retains its bounded wait.

Ordinary HTTP tool calls use four owned workers, with 128 total admitted requests
and 32 per stable principal. Access ownership is credential/session scoped;
quota ownership is independent of session rotation. Duplicate active request IDs
are rejected. Queued HTTP calls revalidate their accepted credential and intersect
the old capability with current authority before dispatch. Task controls use the
short dispatch path, so long tool calls and result waits do not reserve their
workers. These are internal admission bounds for existing behavior, not new
customer capabilities.

Stdio keeps ordinary tool effects serialized through one worker. Its sole reader
continues handling ping, cancellation and task controls while a tool runs; it
routes elicitation responses to the matching worker without nested stdin reads.
A maximum of 64 pending stdio dispatch wrappers and the shared admission limits
bound the queue. A stop received before async admission still binds to that exact
request. A new stdio session cannot start while an earlier session's request
worker remains active.

`notifications/cancelled` is scoped to the originating caller/session and request
ID. Closing HTTP JSON/SSE responses or stdio requests asks their ordinary workers
to stop. Completed requests are not replayed or relabeled. Detached task-augmented
calls have independent handles: a dropped creation response or disconnected
result waiter does not cancel their task. Poll/list within the authorized task
session remains the recovery path. Explicit task cancellation, task expiry and
server shutdown ask those workers to stop. HTTP application lifespan and the
stdio CLI invoke server shutdown; direct embedders should call `shutdown()`.

Cancellation is cooperative. Arbitrary synchronous code, blocking native calls,
or independently spawned external work cannot be force-killed or proven rolled
back by this API. Such a worker remains counted; its cancellation result reports
unknown effects. Server shutdown rejects new admissions and drains cancelled
queued work, but does not claim a hard process-exit deadline for uninterruptible
code. Live upstream cancellation, customer providers and OS-level process-tree
termination are not qualified.
