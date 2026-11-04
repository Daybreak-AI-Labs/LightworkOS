# Signal and IRC transport supervision

Each configured adapter instance owns one transport reader and one serial
agent worker. Durable admission happens before a message enters the bounded
32-record memory queue. Overflow remains in the inbox and is visible through
delivery receipts; it is not discarded or treated as completed work.
After restart or overflow, recovery scans the receipt namespace's hard
10,000-record bound, retaining at most 32 identity/time pairs and reading one
record at a time. It selects the oldest accepted work before new work.
Normal queueing stays in intake order. A definite delivery retry holds later
work for that conversation until the earlier attempt can proceed.

Readers do not wait for agent execution. Current sender and configured
account policy is rechecked at execution and delivery. These guarantees are
per configured adapter instance; configure one active transport instance per
account. The shared compare-and-swap execution claim additionally prevents
multiple workers executing the same event.

Signal continuously drains stdout and stderr separately. Stderr is counted
without retaining or logging potentially sensitive content. Incoming messages
require a sender-bound provider timestamp. Up to 32 concurrent JSON-RPC
requests are correlated by request ID, with bounded write and response waits.
A send only completes after its matching result. Explicit invalid-request
rejections are retryable; other errors or a missing response retain an unknown
outcome. No uncertain send causes another agent execution.

IRC answers PING while the worker runs. Account-tag authorization is required,
self messages and unconfigured rooms are ignored, and saved direct-message
replies recheck the current nickname's account with correlated WHOIS before
each chunk. If the server cannot prove that binding, the reply stays unsent.
Reply formatting preserves Unicode content within the protocol's byte limit.

IRC `msgid`, when supplied, provides external deduplication identity. Without
it, the adapter uses a connection identity and sequence: that preserves local
admission but cannot deduplicate server replay across reconnects. Receipt
routing records this distinction. A successful socket drain only confirms a
local wire write. Each chunk records that fact, while the outer reply remains
`delivery_unknown`; it is never labelled confirmed remote delivery or
automatically replayed.

Shutdown stops intake, gives accepted work a bounded drain, cancels and joins
owned workers/readers, and retains uncertain execution claims. Cooperative
recovery scans are retained and joined separately from their waiting task.
Signal terminates its owned child, then kills and awaits it if necessary.
Failure to confirm an owned component's exit is reported explicitly.

Limits: a specific installed signal-cli version, a live Signal account and a
live IRC server's capabilities and delivery guarantees are not qualified.
