# Owned CLI and plugin execution

The optional `codex_cli` provider and operator-configured TypeScript plugins use
one process owner per child. They remain opt-in; executable selection, plugin
file hashes, secret scrubbing, tool registration and runtime authorization still
apply. No shell expansion is introduced. Existing Windows Codex `.cmd`/`.bat`
shim routing remains supported.

## Codex CLI provider

`complete_async` owns the child directly. Cancellation, halt, a Budget stop,
timeout or excessive output terminates its containment group and joins its pipe
workers before the operation exits. The synchronous API uses the same engine;
it blocks its caller until cleanup completes. It does not leave an asynchronous
completion running in the default executor.

One deadline covers login-lock waiting, login (also capped at 60 seconds), and
execution. `providers.codex_cli.timeout_seconds` remains the configuration knob;
non-finite and non-positive values are rejected. Budget and request-local/global
halt checks run while waiting for I/O. Authentication still travels over stdin,
and the default sandbox remains `read-only` with a private temporary directory.
Failed or cancelled login is not cached as successful login.

Captured stdout is limited to 8 MiB, stderr to 1 MiB, and the final-message file
read to 4 MiB. Pipe queues hold at most sixteen 16-KiB chunks per stream. Final
files and process streams are decoded as UTF-8. These are transport limits, not
an upstream output-token limit; the Codex CLI may already have consumed usage
before the host stops it. Failed execution with no final usage receipt raises
a `UsageAccountingError` subtype. Cancellation, Budget and halt exceptions keep
their original types and carry `usage_status="unknown"`; no zero-token completed
response is fabricated. Successful reported usage still passes through Budget.

## TypeScript plugins

The host understands `maverick-plugin/1` and `/2`. A manifest without a version
retains legacy behavior. Other versions are rejected before tool registration.
Version 2 carries a logical request ID, attempt number, absolute deadline and
`replay: "never"`; replies carry `not_started`, `completed` or `unknown` effect
state. The SDK exposes the deadline and an AbortSignal as the second handler
argument. Existing one-argument handlers remain source-compatible. Version 1
requests receive the legacy response shape.

**A process restart never automatically repeats an invocation.** An EOF after a
possible write, broken input, invalid reply, timeout or over-limit output produces
an `ERROR:` with unknown outcome and reconciliation guidance. A new independent
invocation may start a replacement process after cleanup. Request IDs are
correlation identifiers, not durable deduplication or permission to replay.
There is deliberately no advertised idempotency/reconciliation protocol yet, so
neither a caller-supplied ID nor a tool name grants automatic replay permission.
Confirmed version-2 rejection before handler dispatch reports `not_started`.
Internal typed outcomes prevent the outer tool retry policy from replaying even
a plugin whose tool name was classified as a safe read.

The deadline includes the serialized-call lock, startup, stdin writing and
response reading. Queue expiry does not kill another active invocation. A
timeout during execution kills the process and its containment group so a late
response cannot be mistaken for another call. Each persistent child owns exactly
one stdout reader, one stderr reader and one serialized stdin writer. There is
no per-request `readline` thread. Requests and individual response frames are
limited to 1 MiB; stdout plus discarded stderr are limited to 2 MiB per call.
Discovery output is also bounded. The SDK applies frame bounds before dispatch,
waits for output backpressure, and retains serial handler ownership while an
aborted handler finishes cleanup. A deadline acknowledgement does not imply
rollback of effects already performed.

## Platform and timing limits

Windows children start suspended, join a kill-on-close Job Object, then resume;
descendants inherit the job. POSIX children start a new session and cleanup kills
that owned process group, including surviving descendants in that group. This
is process lifetime management, not a security sandbox against trusted
operator-configured code deliberately escaping its POSIX group with `setsid`.
No unrelated PID enumeration or machine-wide process termination is used.

OS process creation, executable hashing, local filesystem operations and JSON
serialization cannot be preempted by a Python timer. Their elapsed time consumes
the deadline and a request is refused before writing if that deadline expired.
Pipe waiting and lock waiting are interruptible; cleanup has a separate five
second bound. A cleanup failure is explicit and must not be treated as safe to
replay. It never replaces an original Budget/halt/cancellation exception.

Validation uses controlled local Python/Node children and the actual compiled
SDK. It does not authenticate a real Codex account, call a model, validate live
customer plugins, or qualify a deliberately detached POSIX process. Windows
Job Object descendant cleanup is exercised on Windows; platform-specific tests
must also run on supported POSIX hosts.


## Local gRPC plugin execution

The gRPC host follows the same no-replay rule: a transport failure, deadline,
server error or cancellation never repeats the Call. Unknown outcomes carry an
internal immutable attempt receipt, so outer tool retries cannot replay them.
A later independent invocation can rebuild a connection after owned cleanup.
The optional local server uses the shared process-tree owner with bounded pipe
queues; output is capped at 2 MiB per operation and RPC messages at 1 MiB. One
call deadline includes lock wait and startup. Cancellation cancels the local RPC,
closes its channel and joins an owned server's cleanup; it does not prove that
an independently managed endpoint rolled back an effect. Such an outcome stays
unknown and requires reconciliation. Malformed timeout values are rejected.

With the plugin workbench enabled, exact local bundled server source is pinned
before startup and across task/workflow resumes. Its container qualification uses
the actual Describe/Call contract, current configuration and immutable image;
connection-only targets cannot claim version-specific readiness.
