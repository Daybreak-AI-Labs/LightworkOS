# Model proxy request ownership

The optional Python and Go model proxies admit a request before reading its
body: client authentication, route allowlisting and upstream host validation
must succeed. Each admitted request owns one upstream response until completion
or cleanup. Provider bytes are streamed without decoding or accumulating the
entire response. A slow downstream pauses upstream reads; client disconnect,
deadline and server cancellation close the upstream owner. Neither proxy retries
a partially sent request or a failed stream. Go also disables the transport's
implicit replay for caller-supplied idempotency keys.

| Environment variable | Default | Meaning |
| --- | ---: | --- |
| `MAVERICK_PROXY_MAX_REQUEST_BYTES` | 8388608 | Actual admitted body bytes, including chunked requests |
| `MAVERICK_PROXY_MAX_RESPONSE_BYTES` | 67108864 | Actual upstream body bytes |
| `MAVERICK_PROXY_TOTAL_SECONDS` | 600 | Overall request deadline, including body reads and blocked writes |
| `MAVERICK_PROXY_MAX_CONNECTIONS` | 64 | Concurrent admitted requests; excess requests are refused |

Python also accepts the corresponding lowercase fields in `[model_proxy]`.
Limits must be positive and finite. Go's programmatic zero-valued fields select
defaults; explicitly invalid environment values fail configuration validation.
Request headers are bounded to 64 KiB and have a 30 second maximum admission
window (or the shorter total deadline). Normal response writes remain inside
the overall deadline. Error delivery and connection cleanup have a short grace
period; cancellation acknowledgement is not a claim that upstream work rolled
back.

Both listeners close each downstream connection after its request. Python does
not support pipelining. Upstream connections are pooled and redirects are not
followed. Environment HTTP proxy discovery is disabled: configure the explicit
upstream endpoint. Caller authorization, proxy tokens, hop-by-hop headers and
headers nominated by `Connection` are stripped on both boundaries; the upstream
credential is then injected only for the configured endpoint.

Before response headers, refusals produce a bounded HTTP error (401/403,
413 for request size, 502 for upstream failure/invalid size, 504 for deadline,
503 for capacity). Once response headers have been sent, a failure closes an
incomplete stream. It cannot safely change the status code or append a pretend
normal completion. Clients must treat truncation as an indeterminate request
outcome, including when the upstream already charged for work. Python bounds
the small capacity-rejection handler pool. An owned capacity rejection writes
its fixed 503 before draining request headers and a small declared body, so a
delayed body does not postpone that response. Response delivery and ingress
cleanup share a 0.25-second bound, followed by a 0.1-second close bound; this
does not admit upstream work. Blocked writes, socket failures or further excess
connections can still end without a delivered HTTP response.

The public synchronous Python `forward`/`handle` and Go `Forward`/`Handle`/`Do`
interfaces remain buffered compatibility adapters with size checks. Production
listeners use streaming ownership. A caller-supplied legacy buffered transport
has already allocated its response before the adapter can inspect it, and its
own implementation controls cancellation. Do not use that compatibility seam
to claim bounded allocation or cancellation of arbitrary third-party code.

Live provider behavior, hostile operating-system resource exhaustion and
production load are not qualified.
