# Durable channel delivery

Configured messaging adapters use separate durable intake, execution and reply-delivery states. A provider event is bound to the active tenant, configured transport account and external message identity. Input content and routing are sealed by the governed record store. Source attachments use private content-addressed files, checked against their manifest before execution. Raw credentials and arbitrary provider exception text are not stored in delivery receipts.

The inbox is committed before an acknowledgement that would remove the provider's retry opportunity. Each message has one execution identity. A compare-and-swap transition owns execution; existing legacy processed-message claims are treated conservatively and never reopened automatically. Once execution begins, a crash or exception may have left business effects behind. The receipt remains `execution_started_unconfirmed` or `execution_unknown`; an error does not authorize another agent run. A generic error notification can be delivered without changing that unresolved execution state.

The completed reply is committed before sending it. Delivery retries use that saved reply and per-chunk receipts. A typed definitive rejection can become `retryable`; a transport timeout or missing acknowledgement becomes `delivery_unknown`. Confirmed chunks are skipped on retry. Adapters recheck current sender authorization before execution, before delivery and before each chunk. SMTP connection loss after possible acceptance is unknown, not exactly-once delivery. Stable SMTP Message-ID values support investigation. RCS uses stable provider message IDs for repeated attempts.

Recovery scans a bounded rotating metadata window, loads only that window, then advances a persisted cursor after processing. An empty window does not imply an empty inbox. Webhook transports own a recovery task for their lifetime; email saves UIDVALIDITY/UID-bound intake before marking it seen and also performs recovery each poll. Acknowledging intake does not mean an agent has completed or the recipient has received an answer.

Current bounds are 20,000 receipts per tenant namespace by default (configurable with `[channels] max_intake_records` from 1,000 to 100,000), 1,000 account recovery cursors, 1,000,000 characters per durable text/reply, 10 source files under the existing attachment size/aggregate rules, 512 reply chunks, and a normal recovery window of 16 records. Capacity refusal backpressures admission. Unknown execution/delivery records are never removed to make room. Explicit retention compaction after 30 days clears content only for confirmed completed-and-delivered records; the deduplication tombstone remains for another 90 days before compaction can delete it. This does not automatically erase all old claims or permit uncertain effects to replay.

Administrators can inspect a tenant-scoped, bounded status window at `GET /api/v1/channels/delivery-receipts?limit=50&cursor=...`. Pass `receipt_id=chd-...` for one receipt's chunk states and provider identifiers. These responses contain status metadata, not message/reply text or credentials. A receipt that cannot be read (for example while its encryption key is unavailable) is listed as `{"id": ..., "readable": false}` instead of failing the window. Signal and IRC keep replies in order within a conversation: a message waiting behind an earlier one shows `held_behind`, and one that went out after an earlier receipt stayed unreadable for 24 hours shows `went_ahead_of` (see [owned transport supervision](channel-transport-supervision.md)). **Channels > Message delivery** and the Copilot operation **Check held chat replies** say in plain words how many replies are waiting and when they go out. There is deliberately no endpoint that automatically resends an uncertain reply or reexecutes an uncertain run.

Run `maverick channel-maintenance compact --limit 100` under the intended
tenant to compact eligible completed records. Repeated invocations advance a
persisted cursor, so an ineligible prefix does not hide older eligible work.
The limit must be 1–100; zero does not request an unbounded scan. Compaction
first clears eligible content and retains deduplication identities. Once a
fully compacted tombstone has been idle for 90 days, a later pass deletes it
and releases capacity. Monitor the configured admission bound; never erase
uncertain receipts to create space.

Before deleting source files, compaction saves a bounded list of their digests
in the receipt. An interrupted unlink or final receipt write leaves that cleanup
pending; the rotating scan resumes it on its next visit without another
30-day delay, including after a process restart. The receipt is marked compacted only after every listed file
is absent. Completed execution and delivery remain terminal throughout, so
cleanup cannot replay business work. Older compacted receipts without this
cleanup marker are checked for leftover files in their own attachment directory;
only valid digest filenames within the existing attachment count bound are
eligible for removal. Invalid directory entries require operator investigation.
Cleanup failures are reported while the scan cursor advances, allowing later
receipts to be maintained before the rotating scan retries the failed record.

Bootstrap restores apply a hold to each restored delivery and polling record.
The recovery UI supplies the exact readback template for an authenticated
administrator to complete using provider/source evidence. The record,
namespace, source digest, execution/account identity and chunk identifiers
must match; stale, unknown or contradictory outcomes remain blocked. This is
an operator attestation, not an automatic provider query or a guarantee of
external delivery. Original execution and chunk results remain preserved,
and restoring or resolving a record never authorizes replay of its old work.
Polling records require a current source watermark to avoid consuming old
messages as new after restore.

Live provider delivery is not qualified; the local filesystem, SQLite and least-privilege PostgreSQL authorities are the supported stores.

Adapter specifics are in [Gateway recovery](channel-gateway-recovery.md) for
Slack, Telegram, Discord, Matrix and iMessage, and [Bounded social polling](channel-polling.md)
for Mastodon, Bluesky and Threads.
Signal and IRC use [owned transport supervision](channel-transport-supervision.md).
Voice response semantics and conservative bootstrap restore handling are
described in [Live interaction boundaries](channel-live-interfaces.md).
