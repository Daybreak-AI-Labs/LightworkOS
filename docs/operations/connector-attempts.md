# Connector attempts and response limits

The shared REST and GraphQL factories retain immutable, sanitized attempt
metadata until `ToolRegistry.run` finishes its retry decision. Their public
results remain strings. The internal record contains a generated request ID,
attempt number, operation class, HTTP status, error class, parsed Retry-After
delay and whether dispatch/effect completion is uncertain. It does not retain
credentials, URLs, headers or upstream failure bodies.

An explicit REST GET may retry 429, 5xx or transient transport failures, including
GET on a mixed read/write connector. The default ceiling is three attempts in
60 seconds. Retry-After is a lower bound: a delay beyond the remaining budget
prevents another attempt. Authentication failures, malformed responses, response
limits and deterministic errors do not retry. Arbitrary GraphQL documents do
not establish an independently verified read contract and never auto-retry.
No write or idempotency-key retry contract is inferred.

Arguments are copied before validation. Across retries the original target,
authentication and arguments must still match a retained digest. Registry access,
registration identity, principal binding, credential resolution, egress checks and
connector rate limits are re-entered for each attempt. A changed request requires
a fresh invocation. In an Agent dispatch, each retry consumes another tool-call
slot before the next attempt; the original call remains accounted by the Agent.
Calls made directly to a factory function perform a single attempt.

Confirmed writes still require existing consent, PREPARE receipts and remote
If-Match where applicable. If a response is lost after dispatch, the result is
`INDETERMINATE` and requires reconciliation, even when the server may not have
applied the write. Budget, usage-accounting, halt and cancellation signals remain
stop signals. A governed write records an INDETERMINATE receipt on a raised stop
and preserves the original stop even when that receipt separately fails.

## Resource admission

Both factories stream response bodies through a common reader before parsing.
The default wire allowance is 2 MiB and the decoded allowance is 4 MiB. The
reader incrementally bounds identity, gzip and deflate content; other encodings,
multiple compressed members and incomplete compressed documents are refused.
Requests prefer identity encoding. A byte limit may be detected after the next
bounded transport chunk has arrived, but the complete large body is never
required. Declared oversize Content-Length is refused without reading the body.

JSON nesting and approximate structural-item limits are checked before object
allocation. Small valid JSON and text retain the existing output form. Declared
JSON with invalid syntax is refused. HTTP 202 remains pending, metadata mode
preserves selected ETag/revision headers, and the existing valid-JSON output
truncation envelope remains explicit. Exceeding an ingestion limit produces a
failure, not an apparently complete partial business document.

Every socket connect/read/write/TLS wait receives the remaining absolute attempt
deadline. A response trickled below the per-read timeout still expires. Each
invocation owns a fresh, non-proxy HTTP/1 pool with no keepalive reuse and no
transport-level retries. Cancellation closes only its owned socket. DNS
validation, IP pinning, original TLS server name, disabled redirects and scoped
loopback permissions remain in `_ssrf.safe_client`.

**Limit:** the operating-system synchronous DNS resolver cannot be interrupted
by this transport. It can occupy the offloaded worker until it returns; the
deadline/cancellation check then refuses before HTTP I/O. The bounded JSON parser
also checks the deadline after its bounded allocation step; it is not a
preemptive CPU timer. These are not complete wall-clock guarantees for arbitrary
resolver or interpreter stalls. Cancellation does not prove a remote write was
undone. No live upstream, proxy or enterprise TLS deployment is qualified by the
local fixtures.

## Operator configuration

Existing connector setup and enablement are unchanged. Resource limits may be
adjusted in config; values must be positive and finite. Invalid values retain
bounded defaults, and the hard ceilings below cannot be exceeded.

```toml
[connector_limits]
max_attempts = 3
total_seconds = 60.0
attempt_seconds = 30.0
wire_bytes = 2097152
decoded_bytes = 4194304
json_depth = 64
json_items = 100000
```

Hard ceilings are 5 attempts, 300 total seconds, 120 seconds per attempt, 64 MiB
for each byte allowance, depth 128 and 1,000,000 structural items. Agent remaining
wall time can only tighten these bounds. The limits are captured once per logical
invocation; no credential-bearing transport or response is reused between runs.
`governed_rest.RestConnector` also uses the bounded shared reader through
`_rest_execute`; its direct action calls are single attempts. Hand-written
connectors that do not call this shared engine are outside the reader's scope.
