# External agents (bring your own agent)

Agents built on **other** platforms — Salesforce Agentforce, AWS Bedrock
Agents, Microsoft Copilot Studio, OpenAI, LangChain/LangGraph, or a home-grown
runtime — can enroll into Lightwork and come under governance: **they run on
their runtime, governed on ours**. One enrollment writes the Agent Trust entry
(inbound direction, tool/risk/budget ceilings, expiry), the fleet-memory
roster, and platform provenance; per-surface bearer credentials are minted
from the dashboard; and every completed run lands on the Operating Record as
a first-class goal owned by principal `agent:<id>`.

The governance seam is a pre-action **screening endpoint**: the foreign agent
asks *before* acting, and Lightwork applies trust admission, the cumulative
budget cutoff, Shield input scanning (fail-closed on scanner error), and the
`[actions] require_approval_at` approval floor — high-risk actions park a real
approval row that a human decides in the dashboard queue while the agent
polls. Everything is audited.

All endpoints mount on the dashboard server (`maverick dashboard`, default
`http://127.0.0.1:8765`).

## Enabling

Off by default. Turn it on in the installer wizard (the **External-agent
gateway** question in the advanced flow) or directly:

```toml
# ~/.maverick/config.toml
[external_agents]
enable = true
```

or `MAVERICK_EXTERNAL_AGENTS=1`. While off, the `/api/v1/external/*` routes
**404** (they don't exist for this deployment).

## Enrolling an agent

On the **/external-agents** dashboard page (admin permission), enroll with:

| Field | Meaning |
| --- | --- |
| `agent_id` | Stable identifier; becomes principal `agent:<id>` on the record |
| `platform` | `agentforce` · `bedrock` · `copilot` · `openai` · `langchain` · `custom` — provenance, not a behavior switch |
| `description` / `owner` / `department` | Ownership metadata; `department` is the default domain for ingested runs |
| `allow_tools` / `deny_tools` | Tool ceiling checked at screen time. An allow entry may carry **your** risk rating as `name:risk` (e.g. `send_contract:high`) — it floors whatever the agent later declares, so a foreign tool cannot under-declare its way beneath a gate |
| `max_risk` | Risk ceiling (`low` / `medium` / `high`) |
| `max_dollars` | Spend ceiling for reported runs, metered per `budget_period` |
| `budget_period` | `monthly` (default — the meter resets each calendar month, UTC) or `total` (lifetime cap) |
| `max_wall_seconds` | Wall-clock ceiling: a reported `duration_seconds` above it is still ingested (spend is never uncounted) but flagged and counted on the roster |
| `data_scopes` | Memory domains it may touch |
| `expires_days` | Trust entry expiry; expired agents are denied until re-enrolled |

One enrollment writes the Agent Trust entry (direction `inbound` — the agent
calls us; we never dial an enrolled foreign runtime), registers the agent on
the fleet-memory roster (when that plane is on), and stamps the metadata
sidecar. Re-enrolling the same id replaces the ceilings but preserves the
spend meter and run counts. Deleting an enrollment removes trust + metadata;
the fleet roster entry stays (learning history is not rewritten).

The same operations exist as admin API: `GET/POST /api/v1/external-agents`,
`GET /api/v1/external-agents/{id}`, `DELETE /api/v1/external-agents/{id}`.

## Minting the rest credential

From the agent's dashboard detail (or `POST
/api/v1/external-agents/{id}/credentials` with `{"surface": "rest"}`), mint
the bearer the agent will authenticate with. The token value (shape
`lw-rest-…`) is shown **exactly once** — store it in the foreign platform's
secret store immediately; no read path ever returns it again.

- **Rotation** = mint again for the same surface. The new token replaces the
  old one immediately; the old token starts returning 401.
- **Revocation** — `POST /api/v1/external-agents/{id}/revoke` (or the
  dashboard button) denies the agent everywhere at once.
- Surfaces are distinct (`rest` / `a2a` / `grpc` / `mcp`) so a leak on one
  surface cannot authenticate another. The BYOA HTTP API uses `rest`.
- With `[external_agents] mint_approval = true`, every mint first parks a
  dashboard approval — see [Step-up on mint](#step-up-on-mint).

Agent-facing calls send `Authorization: Bearer <rest token>`.

## Platform-native identity

The minted bearer is the default credential, not the only one. Three
**platform-native** modes let an agent authenticate with material its own
platform already holds — each pinned to that agent's trust entry and
verified **offline** (no network at verify time). The gateway resolves every
`/api/v1/external/*` request through one auth chokepoint, in this order:
Ed25519 signed request → HMAC → JWT → minted `rest` bearer. Every refusal is
the same generic `401` — the reply never says whether the id exists or which
stage refused; the precise rule goes to the server log only
(`external gateway: <scheme> auth refused (<rule>)`).

Identity fields live on the agent's Agent Trust entry. A hand-managed entry
is the `[agent_trust] agents` list in `~/.maverick/config.toml`; an agent
enrolled from the dashboard lives in the managed overlay
(`agent_trust.json` under the data dir), which overrides a TOML entry with
the same id. Credential mints, revokes, and restores preserve the fields;
**re-enrolling rewrites the managed entry**, so re-apply identity fields
after a re-enroll.

```toml
[[agent_trust.agents]]
id = "sf-quotebot"
direction = "inbound"
# Connected-app JWT
jwt_issuer = "https://login.salesforce.com"
jwt_audience = "lightwork-prod"
jwks_file = "/etc/lightwork/keys/sf-quotebot.jwks.json"  # local PEM or JWKS
# HMAC (webhook signature format)
hmac_secret_ref = "SF_QUOTEBOT_HMAC_SECRET"  # pragma: allowlist secret — a secret NAME, never the value
# Ed25519 signed requests
pubkey = "<64-hex Ed25519 public key>"
```

Configure any subset — an empty field means that scheme is off for the
agent. Whichever scheme authenticates, the entry must still be active (not
revoked / expired / not-yet-valid) and inbound, and every per-agent ceiling
(tools, risk, budget, containment) applies unchanged.

### Connected-app JWT

Set `jwt_issuer`, `jwt_audience`, and `jwks_file` on the entry and send the
platform's JWT as `Authorization: Bearer <jwt>`. The gateway routes the
token by its `iss`/`aud` claims to the matching entry, then verifies
signature, expiry, issuer, and audience against key material read from
`jwks_file` — a **local** file holding either a PEM public key or a JSON
JWKS document, read at verify time so key rotation is a file swap; no JWKS
endpoint is ever fetched. The **verified `sub` claim must equal the agent id
exactly**, so a token minted for one agent can never authenticate another.
Asymmetric algorithms only (`alg: none` and HMAC algorithms are rejected);
the server needs the `pyjwt[crypto]` extra.

**Salesforce:** a Connected App already doing the OAuth 2.0 **JWT bearer
flow** can present the same style of assertion to Lightwork directly — set
`jwt_issuer` to the assertion's `iss` (the consumer key), `jwt_audience` to
the audience it signs, and point `jwks_file` at the Connected App
certificate's public key. Sign the assertion with `sub` set to the enrolled
agent id (ids are lowercase `a-z0-9._-`, so a Salesforce username does not
work verbatim).

### HMAC (webhook signature format)

Set `hmac_secret_ref` to the **name** of a secret and share the secret value
with the platform. The registry stores only the reference — the name is
resolved through the secret provider (process env, or a mounted secrets dir
via `[secrets]` / `MAVERICK_SECRETS_BACKEND`) at verify time, so rotation
happens in the secret store, never in the registry.

Requests carry three headers over the raw body:

| Header | Value |
| --- | --- |
| `X-Lightwork-Agent-Id` | The enrolled agent id |
| `X-Lightwork-Timestamp` | Unix seconds; the signature covers it |
| `X-Lightwork-Signature` | `sha256=` + hex `HMAC-SHA256(secret, "<ts>." + raw_body)` |

This is exactly Lightwork's outbound webhook signature format: sign
`b"<timestamp>." + body` with HMAC-SHA256 and prefix the hex digest with
`sha256=`. Timestamps older than 300 seconds are rejected; signature
comparison is constant-time.

Existing `X-Maverick-Timestamp` and `X-Maverick-Signature` headers remain
accepted. If both names are sent, their values must match; conflicting values
are rejected before authentication. No signing-key change is required.

Each signed request is also **single use**: the signature is deterministic
over (secret, timestamp, body), so a captured request replayed inside the
freshness window presents the same signature and is refused. Vary the
timestamp per request — a retry after a timeout must be re-signed with a
fresh one rather than resent byte-for-byte.

### Ed25519 signed requests

Pin the agent's raw Ed25519 public key on the entry (`pubkey`, 64 hex
chars) — the same identity the trust plane pins for federation peers. Each
request carries four headers:

| Header | Value |
| --- | --- |
| `X-Lightwork-Agent-Id` | The enrolled agent id |
| `X-Lightwork-Timestamp` | Unix seconds; the matching legacy name is also accepted |
| `X-Lightwork-Nonce` | A fresh random string (≤128 bytes), single-use |
| `X-Lightwork-Request-Signature` | Hex Ed25519 signature over the message below |

The signed message is domain-separated and versioned:

```
lightwork-external-request-v1|<agent_id>|<timestamp>|<nonce>|<hex sha256(raw body)>
```

(`maverick.external_identity.envelope_message` builds these exact bytes —
import it in a Python client rather than reimplementing.) Everything an
attacker could swap — identity, freshness, replay key, payload — is under
the signature, and the version prefix means a request signature can never
double as a handoff, approval, or federation signature. Freshness:
timestamps more than 60 s in the future or older than 300 s are rejected.
The nonce is **single-use per agent** — a replayed nonce is refused.

Both signed schemes claim each request in a durable, per-agent ledger
(`external-replay.json` under the data dir) before it authenticates, so a
claim made on one dashboard worker binds every other worker. The ledger
fails closed in both directions: a per-agent budget that is still full
after pruning expired keys refuses new requests rather than evicting a live
key, and a ledger that cannot be read or written refuses rather than
letting an unprovable request through. The budget is **per agent**, so a
saturated agent can never lock other agents out. The server needs the
`cryptography` package.

### Requiring the strong credential

Once an agent holds a native credential, turn its minted bearer off:

```toml
[external_agents]
require_signed = true
```

An agent whose entry pins a `pubkey` or names a `jwt_issuer` may no longer
authenticate with its minted `rest` bearer alone — it must present the
signed request or JWT. Agents holding only bearers are unaffected, so the
rollout is per-agent: pin the strong credential, switch the platform over,
then flip `require_signed` on. Strict bool; a malformed value engages the
refusal (fail closed — it is a tightening switch).

### Step-up on mint

Minting a credential is itself a sensitive action. With

```toml
[external_agents]
mint_approval = true
```

every mint (and rotation — same operation) takes a human decision first:

1. **Request the mint** as usual — `POST
   /api/v1/external-agents/{id}/credentials` with `{"surface": "rest"}`
   (admin), or `maverick external-agents mint <id> --surface rest`. Nothing
   is minted: the call parks a **world approval** at high risk (the
   deployment's dual-control quorum for high risk applies) and answers
   `409` with `{"status": "approval_required", "approval_id": N}`; the CLI
   prints the same approval id.
2. **A decision-maker approves** approval `N` in the dashboard Approvals
   queue — provenance `external_agents`, action
   `mint-credential:<agent_id>:<surface>`, requested by the admin who asked.
3. **Replay with the id** — re-POST with `{"surface": "rest",
   "approval_id": N}` (or re-run the CLI with `--approval-id N`). The token
   mints and appears in this response only; the audit event records the
   `mint_approval_id`.

Approvals are **one-shot and exactly bound**: approval `N` covers one
agent + surface pair (an id granted for a different agent or surface is
refused), and it is spent on use — replaying the same id is refused; park a
new approval instead. A denied approval refuses the mint. The CLI goes
through the same core gate, so there is no ungated mint path. Strict bool;
a malformed config value engages the gate (fail closed).

## Platform setup

`GET /api/v1/external/openapi.json` (same bearer auth) returns an importable
OpenAPI 3.0 description of the three agent-facing endpoints — it drops
directly into Agentforce External Services and Bedrock action groups.

For hand-rolled runtimes, the [external agent
quickstart](clients/external-agent-quickstart.md) ships copy-paste Python and
TypeScript helpers for the screen-then-act, report-after loop.

### Salesforce Agentforce

1. **Credential** — Setup → Named Credentials: create an External Credential
   with a custom `Authorization: Bearer lw-rest-EXAMPLEEXAMPLE` header and a
   Named Credential pointing at your Lightwork base URL
   (`https://lightwork.example.com`).
2. **External Service** — Setup → External Services → New from API
   specification: paste the JSON from `GET /api/v1/external/openapi.json`,
   select the Named Credential. Salesforce generates invocable actions for
   the screen, run-report, and approval-poll operations.
3. **Actions** — in Agent Builder, add the generated screen and run-report
   actions to the agent's topic (action set).
4. **Instructions** — tell the topic to call **screen** (tool name, one-line
   detail, risk) before any consequential action and only proceed on
   `allowed: true`; when `requires_approval` comes back, poll the approval
   action until a human decides, sending the returned
   `approval_binding_sha256` on every poll; call **runs** once with
   title/outcome/cost when the job completes. This screen-only decision is
   advisory because the external runtime still owns the effect. Use
   `/api/v1/external/execute` for a Lightwork-enforced connector effect.

Paste-in packaging (deployable Apex invocable classes and Setup instructions)
is in `examples/external-agents/agentforce/` in the repository.

### AWS Bedrock Agents

1. Save the schema: `curl -H "Authorization: Bearer lw-rest-EXAMPLEEXAMPLE"
   https://lightwork.example.com/api/v1/external/openapi.json >
   lightwork-external.json` and upload it to S3 (or paste inline).
2. Create an **action group** on the Bedrock agent from that OpenAPI schema.
   Executor: a small Lambda that forwards each operation to the matching
   Lightwork endpoint, reading the bearer from **Secrets Manager** (never
   hard-code it) — or use *return of control* and let your orchestrating app
   do the forwarding.
3. Agent instructions as above: screen before consequential actions, report
   the run at completion.
4. Rotation = mint a new rest token and update the Secrets Manager value.

Paste-in packaging (SAM template, forwarder Lambda, and action-group schema)
is in `examples/external-agents/bedrock/` in the repository.

### OpenAI / LangChain

Call the two endpoints from your tool layer:

```python
import requests

BASE = "https://lightwork.example.com"
HEADERS = {"Authorization": "Bearer lw-rest-EXAMPLEEXAMPLE"}

def screen(tool: str, detail: str = "", risk: str = "low") -> dict:
    r = requests.post(f"{BASE}/api/v1/external/screen",
                      json={"tool": tool, "detail": detail, "risk": risk},
                      headers=HEADERS, timeout=10)
    r.raise_for_status()
    return r.json()

def report_run(title: str, outcome: str, **fields) -> dict:
    r = requests.post(f"{BASE}/api/v1/external/runs",
                      json={"title": title, "outcome": outcome, **fields},
                      headers=HEADERS, timeout=10)
    r.raise_for_status()
    return r.json()
```

Gate each consequential tool call (in LangChain, at the top of the tool
function or in a callback handler) and report once at the end:

```python
verdict = screen("send_email", detail="renewal note to ACME", risk="medium")
if verdict.get("requires_approval"):
    ...  # hold; poll GET /api/v1/external/approvals/{approval_id}
elif not verdict["allowed"]:
    ...  # skip the action; verdict["rule"] / verdict["reason"] say why

report_run("Renewal outreach", "success",
           steps=["pulled list", "drafted", "sent 14"],
           cost_dollars=0.42, input_tokens=18000, output_tokens=5200,
           tool_calls=9, department="sales")
```

### Anything else: curl

Screen a proposed action:

```bash
curl -sS -X POST https://lightwork.example.com/api/v1/external/screen \
  -H "Authorization: Bearer lw-rest-EXAMPLEEXAMPLE" \
  -H "Content-Type: application/json" \
  -d '{"tool": "send_email",
       "detail": "Quarterly summary to the finance list",
       "risk": "medium"}'
```

```json
{"allowed": true, "rule": "allow", "reason": "within ceilings"}
```

At or above the approval floor the action parks instead:

```json
{"allowed": false, "rule": "approval_required",
 "reason": "risk high is at/above the high approval floor; awaiting a human decision",
 "requires_approval": true, "approval_id": 42,
 "approval_binding_sha256": "<sha256-of-the-reviewed-approval-card>"}
```

Poll while a human decides in the dashboard queue:

```bash
curl -sS https://lightwork.example.com/api/v1/external/approvals/42 \
  --get --data-urlencode "binding_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
  -H "Authorization: Bearer lw-rest-EXAMPLEEXAMPLE"
```

```json
{"approval_id": 42, "status": "pending", "risk": "high",
 "approval_binding_sha256": "<sha256-of-the-reviewed-approval-card>",
 "target_sha256": "...", "parameters_sha256": "..."}
```

`status` moves to `approved` or `denied`. A stale binding returns 409 and a
different enrolled agent receives 404. Approval here advises the external
runtime; it does not make the runtime's later action a Lightwork-enforced
effect. Use `/api/v1/external/execute` and its commit route for that guarantee.
Report a completed run:

```bash
curl -sS -X POST https://lightwork.example.com/api/v1/external/runs \
  -H "Authorization: Bearer lw-rest-EXAMPLEEXAMPLE" \
  -H "Content-Type: application/json" \
  -d '{"title": "Renewal outreach for Q3 at-risk accounts",
       "outcome": "success",
       "summary": "Drafted and sent 14 renewal emails; 2 escalated.",
       "steps": ["pulled at-risk list", "drafted emails",
                 "sent 14", "escalated 2"],
       "cost_dollars": 0.42, "input_tokens": 18000,
       "output_tokens": 5200, "tool_calls": 9,
       "department": "sales"}'
```

```json
{"ok": true, "goal_id": 118, "over_budget": false}
```

`outcome` is `"success"` or `"failure"`; only `title` and `outcome` are
required. Titles, summaries, and steps are capped in length; up to 50 steps
are kept.

## Governed execution

Screening answers *may I?* and trusts the agent to act on its own platform.
**Governed execution** is the enforcement tier above it: Lightwork performs
the action itself, on the agent's behalf, through the governed connector
path — host IP-pinning, enterprise egress allowlists, no redirects — with a
tamper-evident **PREPARE/COMMIT receipt** written around every effect. What
touches your system of record is Lightwork's audited egress boundary, never
the foreign runtime's HTTP stack.

Off unless you name connectors (screening alone needs nothing here):

```toml
# ~/.maverick/config.toml
[external_agents]
enable = true
connectors = ["salesforce", "servicenow"]
```

or `MAVERICK_EXTERNAL_CONNECTORS=salesforce,servicenow`. Empty = screen-only;
unknown names are dropped (a typo can never open an egress path). Each
connector reads the **same credentials as the enterprise connectors** —
`SALESFORCE_INSTANCE_URL` + `SALESFORCE_ACCESS_TOKEN`,
`SERVICENOW_INSTANCE_URL` + `SERVICENOW_TOKEN` — so a system you connected
once is already credentialed for the governed path.

Three agent-facing endpoints (same `rest` bearer):

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/external/execute` | Perform a read, preview a write, or park a write |
| `GET /api/v1/external/executions/{execution_id}` | Poll a parked execution |
| `POST /api/v1/external/executions/{execution_id}/commit` | Digest-bound replay once approved |

**Reads run immediately.** `op: "get"` is low-risk and executes in one round
trip (after the same admission chain as screening):

```bash
curl -sS -X POST https://lightwork.example.com/api/v1/external/execute \
  -H "Authorization: Bearer lw-rest-EXAMPLEEXAMPLE" \
  -H "Content-Type: application/json" \
  -d '{"connector": "servicenow", "op": "get",
       "path": "/api/now/table/incident?sysparm_limit=1"}'
```

```json
{"allowed": true, "rule": "executed", "status": "executed", "result": "..."}
```

**Writes always park a human decision** (`post`/`put`/`patch`/`delete`; in
v1 there is no auto-approval path for external writes). Phase one submits
the request:

```bash
curl -sS -X POST https://lightwork.example.com/api/v1/external/execute \
  -H "Authorization: Bearer lw-rest-EXAMPLEEXAMPLE" \
  -H "Content-Type: application/json" \
  -d '{"connector": "servicenow", "op": "post",
       "path": "/api/now/table/incident",
       "body": {"short_description": "Renewal follow-up for ACME"}}'
```

```json
{"allowed": false, "rule": "approval_required", "requires_approval": true,
 "approval_id": 57, "execution_id": "kF3x9q2mWv8Zt1Ao", "expires_at": 1780650000.0}
```

The approver sees the network-free effect preview and the request's sha256
fingerprint in the dashboard queue. Poll `GET
/api/v1/external/executions/{execution_id}` until `approval_status` moves to
`approved`, then phase two — re-send the **identical** request to commit:

```bash
curl -sS -X POST \
  https://lightwork.example.com/api/v1/external/executions/kF3x9q2mWv8Zt1Ao/commit \
  -H "Authorization: Bearer lw-rest-EXAMPLEEXAMPLE" \
  -H "Content-Type: application/json" \
  -d '{"connector": "servicenow", "op": "post",
       "path": "/api/now/table/incident",
       "body": {"short_description": "Renewal follow-up for ACME"}}'
```

```json
{"allowed": true, "rule": "executed", "status": "executed",
 "execution_id": "kF3x9q2mWv8Zt1Ao", "result": "..."}
```

The approval is **digest-bound**: the committed request is hashed and
compared to what the human authorized. Any change — one field, one
character — voids the parked execution and counts as misbehavior (toward
auto-containment), so what executes is exactly what was approved, never a
swapped payload. The commit also re-runs the full admission chain
(containment, revocation, ceilings, budget re-bind at commit time): the
human's yes is necessary, not sufficient. A repeated or racing commit
reports the terminal status instead of re-firing.

Semantics worth knowing:

- `"preview": true` on a write returns the effect description and
  `request_sha256` with **no network call and no approval** — show a human
  (or your own planner) what would happen before submitting.
- A parked execution expires after **24 hours**; at most **20** may await
  decisions per agent (rule `execution_backlog` past that). Bodies are JSON
  objects, capped at 32 KB.
- `goal_id` binds the effect to one of the agent's live runs so the receipt
  and a step-trail event land on that Operating Record row.
- Every execution writes PREPARE/COMMIT lineage receipts (field *names* and
  the request fingerprint — never body values) and an
  `external_action_executed` audit event; responses are secret-redacted
  before they return.

## What shows up where

- **Operating Record** — each reported run is a goal owned by `agent:<id>`
  with a status event per step and a costed episode (dollars, tokens, tool
  calls). Overview, Spend, Workforce, and Savings boards and the audit binder
  count foreign agents exactly like native ones.
- **/external-agents page** — roster with platform, owner, department,
  lifecycle (active / expired / revoked), spend vs. ceiling, run count, and
  which surfaces hold credentials (never the token values); per-agent detail
  shows recent episodes.
- **Approvals queue** — parked screen rows appear with provenance
  `external_agents`, requested by `agent:<id>`; the human decision there is
  what the agent's poll sees.
- **Audit trail** — event kinds `external_agent_enrolled`,
  `external_credential_minted`, `external_run_ingested`, and
  `external_action_screened` (every screen decision, allow or deny); trust
  denials also record `agent_trust_denied` rows.

## Budget semantics

`max_dollars` is a ceiling on **reported spend, per budget period** — not
per-run. Under the default `monthly` period the meter resets each calendar
month (UTC); under `total` it is a lifetime cap. Every ingested run adds its
`cost_dollars` to the meter; the ingest response flags `over_budget: true`
once it crosses the ceiling, and from then on **screening denies with rule
`budget`** — the agent is refused further actions rather than silently
accumulating spend. Run ingest itself stays open (accounting never stops,
so spend is never uncounted). To lift the cutoff early, either re-enroll
with a higher `max_dollars` or use **Reset budget** on the console (`POST
/api/v1/external-agents/{id}/reset-budget`, audited) — lifetime totals are
always preserved.

## Live runs (start / heartbeat / finish)

`POST /runs` reports work after the fact. For work you want visible — and
stoppable — **while it happens**, open a live run:

1. `POST /api/v1/external/runs/start` `{title, summary?, department?}` →
   `{goal_id, heartbeat_seconds}`. The goal lands **active** on the
   Operating Record immediately.
2. `POST /api/v1/external/runs/{goal_id}/heartbeat` at least every
   `heartbeat_seconds` (default 15, one quarter of the default 60-second
   orphan-reclaim window). The returned interval includes room for normal
   request delay; schedule the next beat from the last successful response.
   The reply is the kill switch: `{"continue": false, "reason": ...}` means
   **stop working now** — containment, revocation, expiry, and reclaimed or
   finished runs all return false. An agent that ignores it stops refreshing
   its liveness anyway: the run is reclaimed to `blocked` with a restart
   marker.
3. `POST /api/v1/external/runs/{goal_id}/finish` with the same body as
   `/runs` minus `title` — outcome, steps, cost, `duration_seconds`,
   `idempotency_key`. Cross-agent heartbeats and finishes are refused; a
   finished run cannot be finished again.

Heartbeats are limited to 240/minute per agent.

## The learning plane over REST

With `[fleet_memory] enable = true`, enrolled agents reach the governed
learning plane through the same gateway bearer as over MCP:

- `POST /api/v1/external/memory/ingest` `{kind: success|failure|lesson,
  goal_text, reflection?, tools_used?, domain?}` deposits an experience
  record. Vendor provenance is stamped from the **enrollment's platform**,
  never the caller's claim; the record passes the same redaction, injection
  tripwires, and data-scope gates as the MCP path, and unenrolled or
  contained agents are refused. Deposits feed the dream cycle and are
  provable per vendor via `maverick proof --fleet`.
- `POST /api/v1/external/memory/recall` `{query, domain?}` returns
  department-scoped lessons for the asking agent (`{context, reason}`; an
  empty context with a reason is a refusal, not an error). Every read is
  audited with the reader's identity.
- Both are limited to 60 requests/minute per agent. The console shows total
  lessons shared; each scorecard shows that agent's contributions.

## Approval notifications

A parked approval notifies people instead of waiting for someone to open the queue:

- The ops push transport (`[alerts]` / `[notifications]`, when configured)
  gets a high-priority "external agent waiting on approval #N" push.
- Set `[external_agents] approval_webhook = "https://…"` and the deployment
  fires a **signed** `external_approval.created` callback (HMAC-SHA256 via
  the shared `[webhooks] secret`, timestamped, SSRF-guarded) with a
  provenance-only payload: `approval_id`, `agent_id`, `tool`, `risk`,
  `department` — never the free-form detail text. Point it at your
  platform's inbound hook to unblock the agent the moment a human decides.
- The dashboard approval queue labels these rows "external agent · BYOA
  gateway".

## Retries, rate limits, and containment

- **Idempotent ingest** — send a stable `idempotency_key` per logical run
  and a retried `POST /runs` returns the original record (`duplicate:
  true`) instead of double-counting spend. Keys are per-agent; keep them
  under 128 characters.
- **Rate limits** — per agent, per minute: `screen` 120, `runs` 60,
  `approvals` 120 (the schema route is per-address, 30). Exceeding one
  returns `429` with `Retry-After: 60`; back off and retry.
- **Auto-containment** — repeated *misbehavior* denials (ceiling breaches,
  budget, blocked payloads; 5 within 24 hours) flip the agent to
  **contained**: every call is refused with rule `contained` until an
  administrator presses **Release** on the console (`POST
  /api/v1/external-agents/{id}/release`). Approval-floor parks and
  platform-side scanner errors never count toward containment. Containment,
  release, and budget resets are all audited
  (`external_agent_contained` / `external_agent_released` /
  `external_budget_reset`).

## Fail-closed notes

The external boundary fails closed throughout:

- An unenrolled, revoked, expired, or wrong-direction agent is denied.
- A Shield scanner **error** during screening denies (`rule:
  "screen_error"`) — it never waves an external action through unscreened.
  (The Shield itself stays optional, as everywhere: without it installed,
  screening degrades to the secret-redaction + injection-tripwire layer.)
- Ingested text (title, summary, steps) is secret-redacted and
  injection-screened; a tripwire hit **rejects** the run rather than
  laundering the payload into the record.
- A malformed enrollment sidecar is treated as empty-but-alarmed (logged);
  identity still gates at the trust plane.
- The registry binds at this gateway even when the global Agent Trust Plane
  is disengaged — it is an external boundary in its own right.

## Troubleshooting

| Symptom | Meaning | Fix |
| --- | --- | --- |
| `404` on `/api/v1/external/*` | Plane is off | Enable `[external_agents]` and restart the dashboard |
| `403` | A governance refusal; the response `detail` gives the reason | Act on the reason, for example on the agent's row on **/external-agents** |
| `401` | Missing, wrong, rotated, or revoked rest token (the reply never says which) | Mint a new rest credential; minting replaces the old token immediately |
| `401` with a native credential | Generic by design — the server log names the rule: `external gateway: <scheme> auth refused (<rule>)` | Match the log rule against the rows below |
| log rule `stale` / `future_ts` | Timestamp outside the freshness window (300 s age, 60 s forward skew) | Sync clocks (NTP) and sign at send time, not enqueue time |
| log rule `replay` | The request was already claimed (envelope nonce reused, or an HMAC request resent byte-for-byte) | Use a fresh nonce / timestamp per request |
| log rule `replay_budget_full` | This agent's single-use ledger is full of unexpired keys | Slow the agent down; keys prune as they age past the freshness window |
| log rule `replay_store_unavailable` | The single-use ledger could not be read or written — requests refuse rather than risk a replay | Check the data dir's permissions and free space |
| log rule `bad_signature` | HMAC or Ed25519 signature does not verify — wrong key/secret or the signed material differs from the raw body | Rebuild the signing input byte-for-byte (`"<ts>." + body` for HMAC; `envelope_message` for Ed25519) and send exactly those body bytes |
| log rule `secret_unresolved` | `hmac_secret_ref` names a secret the provider cannot resolve | Export the env var (or mount the secret file) named by the ref |
| log rule `jwks_unavailable` | `jwks_file` absent, unreadable, or neither PEM nor JWKS | Fix the path/contents; the file is read at verify time |
| log rule `no_matching_entry` | No entry's `jwt_issuer` + `jwt_audience` match the token's `iss`/`aud` | Align the trust entry with the claims the platform actually signs |
| log rule `subject_mismatch` | The verified `sub` differs from the entry id | Mint the JWT with `sub` set to the enrolled agent id |
| log rule `jwt_unavailable` / `no_crypto` | Optional server dependency missing | Install `pyjwt[crypto]` (JWT) / `cryptography` (Ed25519) |
| log rule `require_signed` | `[external_agents] require_signed` refuses the minted bearer for an agent with a pinned key or JWT issuer | Present the strong credential (or turn the switch off) |
| `409` `approval_required` on mint | Not an error — `mint_approval` parked approval #N | Have a decision-maker approve it in the queue, then re-run the mint with `approval_id` |
| "approval #N has already minted a credential" | Mint approvals are one-shot | Run the mint without an approval id to park a new one |
| rule `not_in_registry` | Agent has no trust entry | Enroll it on /external-agents |
| rule `revoked` | Trust entry revoked | Re-enroll (or clear the revocation) and mint a fresh token |
| rule `expired` | Past `expires_at` | Re-enroll with a new expiry |
| rule `direction` | Entry is not inbound | Enrollments are inbound-only; fix hand-edited trust entries |
| rule `capability` | Tool denied, or risk (after your `name:risk` floor) above `max_risk` | Adjust `allow_tools`/`deny_tools` or the risk ceiling |
| rule `budget` | Period spend exceeds `max_dollars` | Wait for the monthly reset, **Reset budget** on the console, or re-enroll with a higher ceiling (all audited) |
| rule `shield` | `detail` blocked by the input screen | Inspect the detail text; strip secrets/injection content |
| rule `screen_error` | Shield scanner errored — fail-closed deny (does not count toward containment) | Check the shield install and logs, then retry |
| rule `approval_required` | Not an error — risk at/above the `[actions] require_approval_at` floor | Poll `GET /api/v1/external/approvals/{approval_id}` until a human decides |
| rule `contained` | Repeated denials tripped auto-containment | An admin reviews and presses **Release** on /external-agents |
| rule `connector_not_enabled` | Connector not named in `[external_agents] connectors` | Add it there (or `MAVERICK_EXTERNAL_CONNECTORS`) and restart the dashboard |
| rule `digest_mismatch` | Committed request differs from what was approved — the parked execution is voided and it counts as misbehavior | Re-submit via `/execute` and commit the byte-identical request |
| rule `execution_expired` | Parked longer than 24 hours before any effect | Submit the request again |
| rule `receipt_unavailable` | The PREPARE receipt could not be persisted — nothing fired (fail-closed) | Check the lineage store and logs, then retry the same commit |
| rule `detail_too_long` | `detail` exceeds 4000 chars (bounded before scanning) | Shorten the free-text detail |
| rule `park_failed` / `park_incomplete` | The approval could not be created when parking — nothing was authorized and nothing fired | Submit the request again |
| status `indeterminate` | The worker died between claiming the commit and writing its outcome — the effect may or may not have fired | Verify in the system of record before doing anything else; the entry never re-fires |
| `429` | Per-agent rate limit | Honor `Retry-After`; batch reports or slow the loop |
