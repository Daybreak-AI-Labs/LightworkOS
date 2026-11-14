# Bounded social channel polling

Threads and Mattermost authorize senders using their stable provider user IDs,
not usernames. Replace any existing username entries in their `allowed_user_ids`
configuration with provider IDs before upgrading; usernames may be reassigned.
The dashboard accepts a Mattermost allow-list entry only when it is a
26-character user ID.

Mastodon and Mattermost replies insert an invisible separator after a
model-written `@`, including inside code, so replies cannot notify another
person through a model-written mention; check copied commands before running
them.

Mastodon, Bluesky and Threads persist each authorized input in the channel
inbox before advancing a page checkpoint. A process restart or rate limit
resumes the last covered page boundary. Repeating an incompletely admitted
page is safe because the durable inbox owns execution independently.

Each poll admits at most three pages of at most 50 items per page and has a
15-second source/admission deadline. Mastodon requests 30 items; Threads
requests 25. Continuation remains explicit across bounded polls. Repeated
opaque cursors and a 1,024-page cycle bound are reported as incomplete; they
never certify a completed range. A cursor loop restarts the same uncovered
range on the next scheduled poll, under the usual polling delay/backoff.
No provider-supplied next-page URL is followed with credentials.

Startup history policy is adapter-specific:

- Mastodon initializes its numeric watermark from the newest existing
  notification. Initialization failure stops intake rather than replaying
  history. The watermark advances only after the entire covered range is
  durably admitted. Numeric descending-order checks detect changed ordering.
  Its configured account binding is the HTTPS origin plus a one-way token
  fingerprint: rotating the token establishes a new binding and seed. Old
  unresolved receipts remain held for operator reconciliation.
- Bluesky persists its original startup time as a fixed history floor and
  uses authenticated account DID plus notification URI for identity. It
  follows opaque cursors and does not move the timestamp floor forward:
  late-indexed events after that floor remain eligible. History pages may
  take multiple bounded polls to cover. The in-memory URI set is only an
  optimization after successful durable admission.
- Threads preserves the first-page startup scope and saves that page's
  oldest timestamp as a fixed history boundary. Later cycles can paginate
  bursts without backfilling older history. Reply IDs are opaque for
  ingestion; pagination uses the provider's `after` cursor. Missing or naive
  timestamps cannot establish a history boundary for pagination and produce
  an explicit incomplete state. A single legacy page without timestamps
  stays limited to its prior single-page scope until a safe boundary exists.

Saved reply delivery is independent of polling. Threads receipts each
container creation and each publish, so a definite publish rejection reuses
the saved container. Ambiguous sends remain held. Mastodon and Bluesky also
record their outbound provider operation; they do not treat an HTTP failure
as successful delivery. Current sender/account authorization is rechecked.

Administrators can inspect `GET /api/v1/channels/poll-checkpoints?limit=50`.
This is a bounded tenant metadata window with status and continuation
presence, never provider cursor tokens, account credentials or source text.
`idle` means that range completed, not that the external service has no new
messages. An incomplete status calls for inspecting provider health and the
adapter's startup/history contract, not deleting execution claims.

Qualification uses real local journals and synthetic HTTP pages. It covers
bursts, restart, partial admission, rate limits, cursor cycles, changed
numeric ordering, missing history boundaries and container reuse. Live
provider quotas, timeline consistency and actual account delivery remain
external qualification.
