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

Administrators see held replies in plain words under **Channels > Message
delivery**, and the read-only Copilot operation **Check held chat replies**
(in the Connections family of Copilot actions) gives the same answer under the
same administrator check; with that family off, Copilot answers the question
with a link to Message delivery. The answer says how many replies are waiting,
how many wait behind a reply that cannot be read and the time by which all of
those go out regardless,
how many could not be sent or handled and are tried again, and how many went
out without waiting (counted once sent; IRC confirms no delivery, so an IRC
reply counts once every line of it was written) since the chat service
started. Each running worker publishes these counts and times, with no message
text, person, chat or receipt identity, in a small file sealed with the
deployment key in the `channel-holds` folder next to the configuration file; a
file that is not sealed is never read. A worker publishes nothing until a scan
has read its saved receipts, so a restarted worker counts the replies they say
are waiting from its first published status, and one that cannot read them yet
is reported as not reporting. The status is updated after each scan and before
each reply is worked on, renewed every 30 seconds, even while the worker is
busy with a long reply (a write that fails is tried again every few seconds),
and removed when the worker stops. On the first SIGTERM
`maverick serve` closes its channels as on Ctrl-C, so the dashboard's Stop and
Restart remove it, then ends as SIGTERM always ended it, without waiting for a
local goal or other work still running on a thread, such as a voice note being
transcribed (a repeated SIGTERM does not cut the close short;
whoever sent it ends the process if it does not stop in time). Started with
Ctrl-C ignored, as a script's background job is, it ends on SIGTERM at once,
as before. A chat service that ends without removing its status (every stop
on Windows, where a stop ends the process without a signal it can handle, or a
crash) leaves it behind; when the dashboard's Manage the chat service started
it, the dashboard removes those statuses once it has ended. Otherwise the last
status stays until it is 100 seconds old. One that has not been renewed for
100 seconds is reported as not current, never as nothing held: a chat service
stopped without shutting down cleanly reads as having stopped reporting until
it starts again, and a running worker clears its app's statuses that nobody
renews and any status stamped ahead of its clock. A status
stamped more than a few seconds ahead of the dashboard's clock is ignored, and
a worker renews its status within a few seconds after the clock jumps, as when
a laptop wakes. Replies that were waiting stay counted while their saved
receipts cannot be read. A turned-on chat app with no current status
is named as not reporting, with a restart of the chat service as the next
step: nothing starts an app again after its connection ends, and an app
turned on after the chat service started is not running yet. One turned off
in settings that the chat service still runs is named too. The answer names
the apps it covers: other chat apps' replies are not among them, and nothing
reads the saved replies of an app that is turned off. The status is local to the computer that
runs the chat service; a dashboard on another computer says it is not
reporting.

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
