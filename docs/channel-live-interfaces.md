# Voice interaction boundaries

Voice uses the durable channel journal when receiving external work.
An interaction response does not itself prove that a caller heard or saw it.
Saved execution results remain distinct from transport delivery evidence.
Rich rendering is a wrapper around the base adapters, not an additional inbound
adapter.

## Voice

The inbound voice webhook requires its existing bearer credential. A final user
transcript must include `message.call.id` (or the legacy top-level `call.id`) and
an event `message.id` or stable `message.timestamp`. Partial transcripts do not
execute work. Missing stable identity is rejected before execution; a relay must
preserve these fields across retries. The configured provider, assistant, phone
number and credential digest bind the account; request content cannot substitute
another account.

Concurrent callbacks for one event take one durable execution claim. A callback
received while execution is running gets a processing response. After completion,
repeated callbacks return the saved response under current bearer/caller policy,
without running the agent again. An HTTP response object is not a provider or TTS
receipt: delivery remains explicitly unknown. Changed content under an existing
event identity is rejected. Uncertain execution is never repeated automatically.

Outbound calls record the returned provider call ID. A definitive HTTP rejection
is retryable delivery; a timeout, ambiguous response or missing call ID remains
unknown. Unsupported providers and missing assistant configuration fail before
submission. Local fixtures verify request construction for Vapi, Retell and Bland;
no live provider acceptance or inbound compatibility beyond the implemented Vapi
envelope is qualified here.

## Restore

Restored channel execution/delivery journals, recovery cursors, social polling
cursors and iMessage intake cursors are protected authority. This build keeps a
bootstrap restore containing them in recovery mode; generic confirmation cannot
reopen these records. Admitted, ready, retryable and uncertain records all require
a supported no-replay reconciliation before normal work can resume. The shared
intake, execution and provider-send boundaries enforce the recovery block. This
conservative rule is a restore limitation, not automatic migration qualification.

Tests use local ASGI, fake transport callbacks, real local journal state and
local archive restore. They do not establish native hardware, remote delivery,
external identity-provider or customer acceptance.
