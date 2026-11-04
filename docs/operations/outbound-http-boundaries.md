# Outbound HTTP boundaries

First-party HTTP requests use an explicit admission boundary where possible.
`maverick.governed_http.guarded_sender` checks the current tenant and enterprise
egress policy immediately before invoking the supplied HTTPX operation. It
preserves the sender, timeout, headers, body and response, does not retry, and
does not permit automatic redirects. The `request` helper provides the same
contract when a caller chooses a method by name. Both accept injected senders
for tests and platform adapters; those senders must honor the same no-redirect
contract. A bound HTTPX client configured to follow redirects requires an
explicit `follow_redirects=False` override.

For read-only integrations that follow redirects, `guarded_redirect_get`
asks HTTPX to prepare each next request, then evaluates the current policy
before sending it with automatic redirects disabled. This preserves HTTPX's
cross-origin authorization handling and cookies, bounds the redirect count,
and retains the original response history. It never retries writes.
OIDC discovery additionally requires HTTPS at the initial URL and every
redirect; a downgrade is rejected before the redirected request is sent.

The Jira, GitLab, Notion and Shopify integrations use `GuardedClient` around
their existing HTTPX clients. It keeps their context-manager ownership and
no-redirect configuration while applying the one-hop policy on every supported
operation. Unsupported low-level send and streaming methods fail visibly
instead of bypassing the boundary.

The MCP HTTP client and model-proxy streaming path call
`admit_client_request` immediately before opening each owned HTTPX stream.
It preserves their existing cancellation, timeout, response-stream and client
lifecycle behavior. These callers disable redirects; the admission helper is
not a substitute for redirect-by-redirect enforcement. Exact in-process
HTTPX mock, ASGI, and WSGI transports retain the existing global-guard
exemption, while unknown transports are treated as network-capable.

URL-fetching tools additionally use `_ssrf.safe_client` or its async equivalent
to validate and pin DNS. The pinned transports check policy using the original
hostname before rewriting the connection address, and repeat the check for each
request on a reused client. Egress policy admission is not a substitute for
SSRF protection; use the pinned client whenever a destination is supplied by a
user or model.

The process-wide HTTPX, HTTPX2, requests and urllib hooks remain enabled. They
cover third-party SDKs, asynchronous and persistent client objects, and
first-party operations that have not migrated. Do not remove them until
all outbound calls have an equivalent per-hop boundary, tenant-aware tests,
bounded timeout and cancellation ownership, and coverage for lazy imports and
dependency upgrades. Network isolation remains a separate enforcement layer.
