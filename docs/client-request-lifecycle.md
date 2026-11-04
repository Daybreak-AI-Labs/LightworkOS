# Companion and editor request lifecycle

The browser extension, mobile companion, and IDE run viewers consume the
dashboard's protected APIs. They use the dashboard's own authorization; the
dashboard sends no CORS headers for extensions, no hosted service is involved,
and the native scaffolds are not production-qualified.

## Event history and completion

Browser and mobile viewers drain pages using `next_id` and `has_more`, including
after the goal becomes terminal. A terminal status is not the end of its event
backlog. Viewers never infer contiguous IDs: event IDs belong to the shared
server sequence. Browser and mobile retain at most 1,000 events and approximately
one million display characters, with an explicit notice when older display
history is discarded. Full history remains on the dashboard. A single event or
result preview is limited to 16,000 characters.

VS Code and JetBrains reconnect with both `since` and `Last-Event-ID` set to the
last displayed event. Repeated IDs are not displayed twice. `event: timeout`
reconnects; `event: end` stops only with a matching cursor and
`terminal: true`. Changing the connection, run, or view invalidates late replies.
Cursor caches are bounded and scoped by connection identity plus goal. Bearer
tokens are not persisted in the new cursor caches.

## Owned requests and recovery

Browser and mobile API requests have a 15-second deadline and abort on owner
disposal. The mobile polling hook has a separate 20-second completion deadline
for a noncooperative fetcher. Authentication and permission denials stop
automatic polling and clear the active private view; they do not silently turn
into an offline success. Existing opaque mobile cache scopes and atomic
SecureStore settings remain unchanged. Transient failures can show explicitly
stale cached data for the same connection.

Both IDE stream transports have a 10-second connection deadline and a 45-second
idle deadline, allowing the server's 30-second heartbeat. Closing or replacing
a watch destroys its owned transport and suppresses late output. JetBrains
waits for its old reader and closer to exit before admitting a replacement.
SSE frames are capped at 256 Ki characters; display output is capped at about
one million characters. Browser/mobile JSON parsing is capped at 4 MiB, with
streamed byte enforcement and an early declared content-length check. Older
React Native builds without a streaming Fetch reader are explicitly unsupported:
the client refuses before fetching, stops automatic polling, and asks for an
updated app build. It never falls back to unbounded `response.text()` buffering.
Native device qualification must confirm the packaged transport implementation;
the checked-in Expo scaffold is not asserted to provide that implementation.

## Starting work and halting it

The chat widget still submits `/chat/send`, preserving conversation creation.
It reports success only after the documented same-dashboard redirect to
`/chat/goal/{positive-id}`. An alternate 200 page is not success. The browser
extension requires a valid stable goal ID in its JSON acknowledgement. Both
fence duplicate submissions and retain the draft if the outcome is unknown.

There is no automatic retry of a timed-out start. Before submitting, the
extension stores a random `Idempotency-Key` in extension-private local storage,
scoped by dashboard URL and token digest (at most eight unresolved scopes).
The same-origin widget stores a random `submission_key` in browser local storage;
it stores only that key, not the goal text. Reload/restart retains an unresolved
request. If persistence is unavailable, the client refuses before dispatch.

**Check start status** performs only
`GET /api/v1/goal-submissions/receipt?kind=api|chat` with the original key in the
`Idempotency-Key` header. It recovers the original goal without a second POST.
Missing, denied or unavailable receipts keep the request held; a missing receipt
does not prove that an earlier request never ran. Reads bypass caches and the
server marks both success and lookup errors `no-store`. Changing the connection
invalidates late results. A widget receipt under another signed-in user cannot
be read; restore the original session to reconcile that request.

The chat admission transaction and keyed REST admission atomically
create the goal and durable receipt on SQLite/PostgreSQL. The same owner/tenant
and key plus different reviewed payloads or effective execution caps return
409. One winner claims dispatch; duplicates do not create cancelled loser goals.
Old REST processed-message receipts remain readable as `legacy_unverified`, but
a POST using those old keys requires reconciliation rather than new execution.
This adds no database migration beyond the attachment submission schema38.
Receipt acceptance is not proof of execution: draft/admission/dispatch status
is returned explicitly and `execution_confirmed` remains false. A crash after
claiming dispatch still needs existing task/runner recovery; this is not an
automatic outbox retry mechanism. Keys remain until their goal is deleted, at
which point clients must continue holding an unresolved request rather than
inventing a new identity. Extension CORS remains opt-in and token-gated; the
extra header is allowed only on goal admission and receipt-read paths.

`maverick halt --json` and `maverick unhalt --json` return an acknowledgement
only after re-reading the local halt-file state. The result includes `command`,
`acknowledged`, `halt_file_present`, `scope: "local"`, and
`work_stopped: false`. Emacs, Neovim, and VS Code require that checked result and
a successful command exit before announcing the change. A halt request takes
effect at execution checkpoints; it is not proof that external side effects or
all work have already stopped. Clearing it does not restart prior tasks. Older
CLIs without this optional JSON output must be upgraded before using these
editor actions.

## Local verification and remaining platform qualification

`apps/client-contract-tests/` executes actual browser/widget JavaScript, VS Code
TypeScript and Neovim Lua with controlled platform APIs. Mobile tests execute
the actual TypeScript/React hooks/screens against controlled storage and
requests. They cover 401-event backlogs, access denial, obsolete replies,
timeouts, cancellation, single submission, and exact acknowledgements.
`apps/jetbrains-plugin/tests/RunEventStreamTest.kt` exercises actual JVM HTTP
connections against a disposable loopback server, including blocked-reader
close, heartbeat survival, replay, and terminal acknowledgement.

These are not Chrome/Firefox extension-host, VS Code extension-host, IntelliJ
SDK/plugin, Emacs, native Neovim, or iOS/Android packaged-app acceptance.
JetBrains remains a scaffold requiring a real IntelliJ build project and SDK.
