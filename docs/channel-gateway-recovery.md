# Gateway and local messaging recovery

These guarantees use the same [durable delivery journal](channel-delivery.md)
as the webhook adapters. A saved intake acknowledgement is distinct from an
agent result, a provider accepting a reply, and a person receiving it.

| Adapter | Stable intake identity | Acceptance and recovery boundary |
| --- | --- | --- |
| Slack | Verified workspace and bot user, channel and timestamp | `auth_test` binds the transport before Socket Mode connects. Authorized envelopes and bounded file descriptors are saved before the Socket Mode acknowledgement; attachment download and execution follow. A periodic worker recovers admitted work with the saved thread. Every formatted text chunk stores Slack's returned timestamp. |
| Telegram | Public bot-id prefix of the configured token, chat and message id | Input and file descriptors are admitted before download and execution. Reply chunks save Telegram message ids and retain the original reply anchor across restart. Rotating the token suffix keeps the account identity. Private-chat grants never authorize a group member. |
| Discord | Connected bot user and gateway message id | Sender and self-message guards run before admission. Each reply chunk suppresses mentions and saves the returned message id. Recovery waits for the connected account to be ready and rechecks its identity and current allowlist. |
| Matrix | Homeserver and configured bot user, event id | Recent timeline replay still skips old unadmitted messages; already-admitted work recovers from the journal. Each send uses a deterministic Matrix transaction id. An explicit redelivery can safely repeat an uncertain send with that same transaction id; the automatic recovery window conservatively leaves unknown effects for review. Returned error objects are not success receipts. |
| iMessage | Local Messages database path and message GUID | A durable tenant-scoped cursor skips historical messages only at first adoption. Each subsequent cursor advance follows authorized durable admission, or deliberate rejection of an unauthorized sender. Polls read at most 256 messages. Restarted admitted work is recovered independently of the Messages cursor. |

Slack and Telegram preserve their saved reply anchors. Confirmed chunk prefixes
are skipped during a retry of a definitively rejected later chunk. Sender
authorization and account identity are checked again before execution, reply
delivery and every provider call. Handler failures never reopen execution.

An iMessage zero exit status confirms acceptance by the local AppleScript/
Messages call, not delivery to another device. A nonzero status or timeout is
uncertain and is held for review; a missing executable is definitely unsent.
Text and recipient remain literal argv values passed to a fixed script.
The cursor survives process restarts; a manual replacement/reset of the local
Messages database is an operator migration and must reconcile its checkpoint.

No provider message ids or actual Messages-app operation were exercised by the
local acceptance tests: provider responses are synthetic, while the journal,
claims, files, cursors and concurrent replay are real local code paths. Matrix
`tx_id` and response semantics were checked against the available matrix-nio
source. Live service credentials, delivery and macOS permissions remain
deployment qualification.
