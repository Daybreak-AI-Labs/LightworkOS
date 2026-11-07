# Signal and IRC transport supervision

Each configured adapter instance owns one transport reader and one serial
agent worker. Durable admission happens before a message enters the bounded
32-record memory queue. Overflow remains in the inbox and is visible through
delivery receipts; it is not discarded or treated as completed work.
After restart or overflow, recovery scans the receipt namespace's hard
10,000-record bound, retaining at most 32 identity/time pairs and reading one
record at a time. It selects the oldest accepted work before new work.
Normal queueing stays in intake order.

Within one conversation (one chat and one sender), a message is not handled
while an earlier message in that conversation is still waiting: for a retry
after a definite delivery refusal or a failed attempt, or because its saved
receipt cannot be read (for example while its encryption key is unavailable).
Other conversations keep flowing. A reply withheld by the source check (its
task or sources are no longer available to that person) is the one exception:
it is retried, but newer messages do not wait for it.

The worker learns each waiting receipt's conversation whenever it reads it, so
a receipt that later cannot be read still holds its own conversation. When a
read fails and a later read in the same scan works (the key came back
mid-scan), the failed receipts are read again before anything is chosen. A
message that waits records what it waits behind in its own receipt
(`held_behind`: the earlier receipt's identity, its acceptance time, and when
it was first found unreadable), so the status window shows the hold and a
restarted worker that cannot read the earlier receipt still knows which
conversation it holds. When the earlier receipt can be read again, it is
handled first and the waiting messages follow in order.

If the earlier receipt stays unreadable for 24 hours from when the worker
first found it unreadable, its key is taken not to return: the newer messages
stop waiting for it and go out, and each records the receipt it went ahead of
(`went_ahead_of`). The unreadable receipt itself is kept, never removed to make
room; if its key does come back later, it is handled then, after the messages
that went ahead of it. Restoring the key within those 24 hours is the only way
to answer it in order. A receipt this worker has never been able to read, and
that no waiting message names, cannot be tied to a conversation: it is
reported, and holds nothing until it can be read. An earlier message whose
receipt can be read keeps its conversation waiting until it goes ahead; the
status window shows both receipts, and the warning log reports each failed
attempt.

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
