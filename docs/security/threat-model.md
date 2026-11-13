# Lightwork threat model (STRIDE)

This is the working threat model for Lightwork. It's living: when we add
a capability, we update this doc with the new threats and mitigations.
PRs that add tools or providers SHOULD touch this file.

The model uses STRIDE: **S**poofing, **T**ampering, **R**epudiation,
**I**nformation disclosure, **D**enial of service, **E**levation of
privilege.

## Trust boundaries

```
+-----------------+        +--------------------+
| user terminal   | <----> | maverick process   |
+-----------------+        +--------------------+
                                  |
                                  v
                           +-------------------+
                           | provider API      | (Anthropic/OpenAI/...)
                           +-------------------+
                                  |
                                  v
                           +-------------------+
                           | sandbox           | (local subprocess / docker / ssh)
                           +-------------------+
                                  |
                                  v
                           +-------------------+
                           | external sites    | (browser tool, http_fetch, web_search)
                           +-------------------+
```

The user's machine is the trust boundary on the inside. The provider
API and external sites are the trust boundary on the outside. Anything
crossing those needs explicit consent or shield approval.

### Networked / multi-principal boundaries (enterprise + federated)

The single-user picture above is the default. When Lightwork is deployed
as a governed service it grows three more inbound trust boundaries, each
fronted by its own authenticated, fail-closed surface:

```
                         +----------------------------+
   dashboard users  ---> | dashboard (FastAPI)        |  OIDC / proxy / session
   (browsers, OIDC)      |  - per-user owner scoping   |  cookie; RBAC; CSRF
                         +----------------------------+
   API / SDK / MCP   ---> | gRPC goal API + MCP server |  bearer / per-caller
   clients               |  - capability-attenuated    |  trust token; TLS
                         +----------------------------+
   peer Lightwork     ---> | federation + A2A           |  Ed25519 signed
   swarms / agents       |                             |  envelopes; per-peer
                         |  - Agent Trust Plane gate    |  token; pinned keys
                         +----------------------------+
                                      |
                                      v
                         +----------------------------+
   queue workers     <---| queue / dispatcher handoff  |  capability re-
   (arq/Celery)          |  (cross-host)               |  attenuated by worker
                         +----------------------------+
```

**One client per deployment.** The product contract is one tenant per
Lightwork instance; client/tenant state is namespaced on disk under
`tenants/<client>/` and the dashboard owner-scopes every object. Cross-peer
and cross-user data mingling is the threat this whole layer exists to prevent.

Each of these surfaces is **off by default** and **fail-closed**: it serves
nothing until explicitly configured with credentials, and an unauthenticated
or unknown caller is refused before any work is done.

## In-scope assets

- User's filesystem (`~/.maverick/`, the project working directory).
- API keys (in `~/.maverick/.env`, chmod 600).
- Browser session state (default path `~/.maverick/browser/state.json`, mode
  0600; standalone persistence requires `MAVERICK_BROWSER_STATE`, which selects
  the path). Goal sessions use the explicit browser authentication vault.
- Audit log (in `~/.maverick/audit/*.ndjson`, chmod 600).
- World model SQLite db (optional per-column at-rest encryption,
  `crypto_at_rest` / `tenant/kms.py`; AES-256-GCM, per-tenant DEK).
- At-rest / KMS key material (`~/.maverick/keys/`, mode-at-creation 0600;
  the wrapped DEK is never written unwrapped).
- Per-deployment / per-tenant client data — must never mingle across
  peers (federation) or users (dashboard owner scoping).
- Federation + A2A credentials: per-peer shared tokens, pinned Ed25519
  public keys, dashboard `session_secret`, bearer tokens.

## Out-of-scope (won't defend against)

- Local-root attackers (anyone with root on the user's box owns
  everything anyway).
- Hardware attacks (cold boot, evil maid).
- Compromised provider API endpoints — we trust the providers we
  configured to do their job. If Anthropic ships a compromised model,
  we have bigger problems.
- Compromised optional plugins — users who install untrusted plugins are
  responsible for vetting them. Manifest permissions ARE enforced by default
  (`[plugins] enforce_permissions = true`): a plugin requesting an ungranted
  `network`/`fs_write`/`subprocess`/`sensitive_envs` permission is skipped
  (never loaded) unless granted via `[plugins] grant=[...]`; setting
  `enforce_permissions = false` (or `MAVERICK_PLUGINS_ENFORCE=0`) downgrades to
  load-with-warning. These checks compare declared permissions; they do not
  constrain what plugin code can actually do. Import, discovery, and factories
  run in the host process even when tool calls use `[plugins] isolation`.

## Threats by category

> See the networked/multi-principal section below for the enforcement points
> added for enterprise and federated deployments.

### Spoofing

| Threat                                   | Mitigation                                                                  |
|------------------------------------------|------------------------------------------------------------------------------|
| Attacker impersonates the user to a channel adapter (Discord etc.) | Channel auth tokens stored chmod 600; webhook receivers HMAC-signed with replay-bound timestamps. |
| Prompt injection from a fetched URL makes the agent issue tools as the user | Shield scan of inputs and of every tool output. Tool ACLs limit blast radius. |
| Subagent claims a capability it doesn't have | Signed capability tokens make declared capabilities unforgeable.            |
| Webhook receiver believes a forged event | `X-Maverick-Signature` HMAC; `verify_signature()` helper.                    |

### Tampering

| Threat                                       | Mitigation                                                              |
|----------------------------------------------|--------------------------------------------------------------------------|
| Audit log entries get edited or deleted after the fact | Daily-rotated NDJSON, chmod 600, with an Ed25519 hash-chain (audit signing, on by default). |
| Skill/plugin code is modified on disk between installs | Hash-verified on install (`maverick skill add`); signed skills verified against `[skills] trusted_pubkeys`, required with `[skills] require_signed = true`. |
| Browser session cookie is replayed by a third process | Session state is written only when `MAVERICK_BROWSER_STATE` is set (mode 0600); the browser auth vault stores sessions encrypted at rest. |
| World model gets corrupted mid-write       | SQLite WAL mode + autocheckpoint + `PRAGMA wal_checkpoint(TRUNCATE)` on close. |

### Repudiation

> **Tamper-evidence depends on signing.** Audit signing (Ed25519 hash-chain)
> is on by default; with `[audit] sign = false` or `MAVERICK_SECURE_DEFAULT=0`
> the log is plain NDJSON and the rows below are not tamper-evident. Even with
> signing on, third-party attribution requires
> verifying with an **externally-held** pubkey — a key co-located with the
> log only detects accidental/non-privileged edits. Run `maverick audit
> verify --pubkey <hex>` to check the chain.

| Threat                                                        | Mitigation                                                  |
|--------------------------------------------------------------|--------------------------------------------------------------|
| User claims they didn't approve a destructive action           | Audit log records every consent prompt + decision + source (tamper-evident only when signing is on). |
| User claims they didn't spend $X on a run                    | Episode records `cost_dollars` + `(in,out)` tokens per call. |
| Agent took an action no one can attribute                    | Every tool call audit-logged with agent id + goal id (tamper-evident only when signing is on). |

### Information disclosure

| Threat                                                          | Mitigation                                                                       |
|------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| Tool output leaks API keys to logs                              | `secret_detector` scrubs Anthropic/OpenAI/AWS/GCP/Azure/GitHub/JWT before logging. |
| Browser tool leaks session cookies to external sites             | Cookies sent only to the origin they were captured from.                          |
| Telemetry phones home with prompt content                       | Telemetry is opt-in (trajectory donation is off by default; plugin usage counts stay local); anonymous mode (`MAVERICK_ANON=1`) strips user-identifying content from logs. |
| Webhook payload leaks PII                                       | Outbound webhooks send only minimal payload; users control which events fire.     |
| Audit log readable by other local users                         | Audit writing/sealing re-tightens regular files to mode 0600; symlinks, unsafe aliases and hard links are refused.                                  |

### Denial of service

| Threat                                                       | Mitigation                                                                  |
|--------------------------------------------------------------|------------------------------------------------------------------------------|
| Runaway agent burns the user's budget                        | Hard caps on dollars / tokens / tool calls / wall-seconds; budget_status tool. |
| Agent gets stuck retrying a 401 forever                      | retry_classifier marks auth errors terminal.                                  |
| Webhook receiver hangs the run                               | Webhook dispatch is async via a daemon ThreadPoolExecutor; failures logged.   |
| Tool blocks the agent (e.g. shell command hangs)             | Sandbox timeouts; killswitch file (`~/.maverick/HALT`) aborts cleanly.        |
| Compaction balloons memory on long traces                    | Compaction drops old tool output to digests under a total-size ceiling; optional retrieval of older digests. |

### Elevation of privilege

| Threat                                                  | Mitigation                                                                            |
|---------------------------------------------------------|----------------------------------------------------------------------------------------|
| Plugin escapes its declared capabilities               | Residual risk: grants check declarations, not runtime behavior; trusted plugins and an external OS isolation boundary are required. |
| Browser tool reaches private/loopback addresses        | `http_fetch` refuses private IPs by default; `MAVERICK_FETCH_ALLOW_PRIVATE=1` opt-in.  |
| Computer-use tool drives mouse/keyboard outside scope  | Kill switch `MAVERICK_COMPUTER_DISABLE=1`; per-action approval for every input action.   |
| Shell tool reads sensitive files (gold patches, etc.)  | Opaque-mode blocklists for benchmark contexts; tool ACLs.                              |
| Subagent gains tools the parent doesn't have           | Spawn-tools layer; tool ACLs apply at every level.                                     |

## Networked / multi-principal threats (enterprise + federated)

These cover the inbound boundaries in the second diagram: the dashboard,
the gRPC/MCP APIs, cross-instance federation (federation / A2A), and the
cross-host queue. Every mitigation below is
implemented today (not roadmap); the named mechanism is the enforcement
point.

### Spoofing

| Threat | Mitigation |
|--------|------------|
| A peer presents a copyable shared token to impersonate another swarm | Per-peer token, constant-time compared; when the Agent Trust Plane is engaged a pinned-key peer must additionally **sign** the canonical envelope with its Ed25519 key (`federation_envelope.verify_envelope` against the pinned pubkey — a self-carried pubkey is never the trust anchor). |
| Dashboard caller forges another user's identity | OIDC ID-token verification is asymmetric-only (defeats HS256/`none` alg-confusion), all of `exp/iat/aud/iss/sub` required; the browser-login session cookie is HMAC-signed (constant-time verify, expiry-enforced). |
| API/MCP caller spoofs the bearer | Constant-time bearer compare; per-caller `[agent_trust]` tokens give real per-caller identity; fail-closed when nothing matches. |

### Tampering

| Threat | Mitigation |
|--------|------------|
| A captured federation message is **replayed** at the same peer | Every delegation, including token-only peers, is bound to a bounded per-peer `correlation_id` ledger: identical concurrent/retry requests coalesce, while the same id with changed content is refused. Signed peers additionally carry a `created_at` freshness window and signature replay protection. |
| A delegated capability grant is tampered with in transit / on the queue | gRPC and the queue worker **re-intersect** any wire-supplied capability with the receiver's own local policy (`_rpc_capability` / `_worker_capability`); a grant can only narrow, never broaden. |
| Audit chain edited after the fact | Ed25519 hash-chain with cross-file anchoring; `maverick audit verify --pubkey <externally-held hex>` is required for third-party tamper-evidence (a co-located key only catches non-privileged edits). |

### Repudiation

| Threat | Mitigation |
|--------|------------|
| A node drops its half of a cross-swarm delegation | Both halves are audit-logged as `federation_delegate` rows with a shared `correlation_id` (direction `sent` / `received`), so comparing the two nodes' signed logs shows a missing half. There is no automated cross-node reciprocity check. |
| A trust-plane denial isn't recorded | Every inbound/outbound denial lands in the audit chain (`agent_trust.record_denied`). |

### Information disclosure

| Threat | Mitigation |
|--------|------------|
| One federation peer reads another peer's (or a local) goal status/result | `GoalStatus` is owner-scoped — a goal is stamped `federation:<peer>` and only its delegating peer can poll it; anything else is reported as "unknown" (indistinguishable from non-existent). |
| One dashboard user reads another user's goals (IDOR) | Object-level `assert_goal_access` on every goal-by-id endpoint; exact owner match; denials return **404** (not 403) so existence isn't disclosed. Legacy `owner==""` rows are unreachable by authenticated non-admins. |
| A peer reads webhook/push secrets back from config | `get_push_config` masks the token; support bundles redact secret-named keys. |
| Provider session cookies readable by another local user mid-write | Written **mode-at-creation** (`os.open(..., 0600)`), closing the world-readable window the old write-then-chmod left. |
| Cross-tenant data decryption | Per-tenant DEK + AEAD context binding (`tenant/kms.py`); a tenant's key/ciphertext can't open another's (GCM auth fails). |
| A malicious A2A push target probes internal services | Push configuration accepts only a strict bounded schema, forbids URL credentials/control characters, and applies fail-closed SSRF validation before retaining the target. |
| A remote gRPC client sends bearer credentials or goal data over plaintext | Both listener binds and client dials reject non-loopback plaintext by default. TLS/mTLS is the production path; `MAVERICK_ALLOW_INSECURE_GRPC=1` is the explicit trusted-network escape hatch. |

### Denial of service

| Threat | Mitigation |
|--------|------------|
| A deeply-nested signed envelope crashes verification (`RecursionError` in the canonical-JSON digest) before the signature is even checked | Recursion-safe depth guard rejects over-nested envelopes first (`federation_envelope._within_depth`). |
| A hostile A2A client sends a malformed `id`/`message.parts` shape to crash the task engine into a 500 | Parsers are shape-defensive: a non-string id resolves to "not found", a non-list `parts` yields empty text. A standing fuzz harness (`test_parser_fuzz`) holds the "never raises / fail-closed" contract across every untrusted-input parser. |
| An outward surface is flooded | Bounded thread pools + `maximum_concurrent_rpcs` (gRPC/federation/webhooks); SSE/WS offload + a WS concurrency cap (dashboard); A2A applies per-request/task/artifact/global byte ceilings and terminalizes canceled semaphore waiters so cancellation cannot permanently consume capacity. |
| A client-supplied budget/deadline bypasses caps | Clamped down to operator ceilings (A2A `_limits`, federation `clamp_budget`); budget caps are enforced at record time, never bypassed. |
| ReDoS via adversarial text on the scanning surfaces | Secret-detector / shield regexes are anchored (verified <0.15s on 100 KB adversarial inputs). |

### Elevation of privilege

| Threat | Mitigation |
|--------|------------|
| A peer obtains authority the receiver wouldn't grant | Delegations are **narrow-only**: the peer's requested tools intersect the receiver's local grant; the trust registry ceiling tightens it further; `negotiate_boot` refuses a delegation it can't fully equip. |
| A queue worker honors an over-broad grant placed on the queue | The worker re-attenuates by its own local policy when enforcement is on (zero-trust across the queue boundary). |
| A Redis writer plants an executable serialized object before the HMAC verifier runs | Producer and worker both require the bounded, versioned strict-JSON ARQ codec; pickle and every unknown codec are rejected before object reconstruction. |
| Two fleets share a Redis service and consume each other's jobs | A validated deployment queue namespace is mandatory on both producer and worker. Deployments should also use dedicated Redis databases and ACL identities because ARQ job-body keys use global prefixes. |
| A tool escapes the workspace via a symlink swapped after the path check (TOCTOU) | File tools verify containment **through the opened descriptor** (`/proc/self/fd`), immune to a post-check swap; writes `O_CREAT` without `O_TRUNC`, verify, then write — an escaped file is never truncated. |
| An MCP/connector tool defaults to an under-restricted risk | Unclassified + MCP tools default to **high** risk; the capability `max_risk` ceiling drops over-risk tools at registry time; tool-ACL fails **closed** for restricted principals on a config-read error. |
| An external surface served unauthenticated | Federation/A2A/MCP-HTTP all require credentials and refuse to start/serve without them; a client-bound deployment refuses to serve unbound (`require_client_binding`). |

## Threat-model review cadence

- Reviewed at every minor release.
- Reviewed when a new tool, provider, sandbox, or channel ships.
- No external penetration test has been published yet;
  [`audit-readiness.md`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/security/audit-readiness.md)
  defines the scope for one.
