# OIDC verification and request scope

OIDC remains optional. HTTP and WebSocket authentication verify identity in a
worker, then attach the principal and pin the tenant in the original request
task. Route handlers and their child workers inherit that tenant; WebSocket
cleanup resets its pin. Synchronous callers retain the same compatibility API.

Only public signing keys are cached. A process retains at most 16 resolvers,
keyed by issuer, JWKS URI, audience and algorithm policy, with at most 128 keys
per resolver. Keys expire after five minutes and expired keys cannot authorize
requests during an outage. Concurrent cold requests share one fetch. Unknown
key IDs and failed refreshes share a ten-second refresh cooldown, preventing
one request per arbitrary key ID from triggering a fresh fetch. A newly rotated
key ID may therefore be refused briefly during that cooldown. Reusing a key ID
for a different public key becomes visible at the next normal refresh.

The fetch retains a five-second client network timeout. PyJWT's indefinitely
cached per-key mode is disabled. Configuration changes select the corresponding
resolver; signature, issuer, audience, expiry, required claims and exact subject
validation still execute for every token. Browser sessions, revocation, SCIM
lifecycle, current workspace membership and roles are not cached by this layer.
An explicit bearer still takes precedence over ambient proxy/cookie identity.

Each dashboard event loop admits at most eight potentially remote bearer
verifications. Admission waits at most 250 milliseconds before returning 503
with Retry-After. A disconnected request retains its slot until its worker
finishes, preventing cancellation from creating unbounded resolver work. Probes
and local/session authentication retain ordinary worker capacity. Network and
DNS behavior remain subject to the HTTP client's timeout semantics; this is
bounded admission, not cancellation of an operating-system thread.

External identity providers and production key-rotation deployments are not
qualified.
