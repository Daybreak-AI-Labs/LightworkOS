# Multi-tenancy

Lightwork can isolate many tenants (organizations / workspaces / end-users) on
shared infrastructure, or run one instance per tenant. This page is the map of
what is isolated, how to provision, and where the boundaries are.

## Turning it on

Tenancy is **opt-in and fail-open**: with nothing configured, Lightwork is a
single-tenant install and behaves exactly as before.

- `MAVERICK_TENANT_BY_USER=1` (or `[tenancy] by_user = true`) — each channel
  user becomes their own tenant (`<channel>:<principal>`), with isolated world
  DB, memory, audit, and knowledge.
- `MAVERICK_TENANT=<id>` or an explicit `set_tenant(...)` scope — pin a tenant
  for a process / request.
- A bound client (`[client] id` / `MAVERICK_CLIENT_ID`) — one deployment = one
  enterprise client; that client id is the tenant floor.

## What is isolated per tenant

| Concern | Isolation | Where |
|---------|-----------|-------|
| World DB (goals, conversations, facts) | separate `world.db` per tenant | `~/.maverick/tenants/<id>/world.db` |
| Cross-session memory | per-tenant dir | `tenants/<id>/memory/` |
| Audit log | per-tenant, signed/hash-chained | `tenants/<id>/audit/` |
| Knowledge store | per-tenant via Workspace | `tenants/<id>/knowledge.db` |
| Encryption-at-rest key | distinct DEK per tenant (AEAD-bound); per-tenant BYOK + fleet KEK rotation | `tenant/kms.py`, `tenant/kms_fleet.py`, `maverick tenant kms-rotate` |
| **Config & credentials** | per-tenant overlay | `tenants/<id>/config.toml` |
| **Calibration / learning-freeze** | per-tenant | `tenants/<id>/calibration*` |
| **Concurrency ceiling** | per-tenant, from plan | `billing.entitlements` |
| **RBAC role** | per-tenant membership overrides global | `dashboard-tenant-roles.json` |
| Spend cap | per-tenant `max_daily_dollars` (clamps the per-run budget) | tenant registry |
| Postgres rows | row-level security; auto-on under enterprise, else opt-in | `MAVERICK_PG_RLS` / `MAVERICK_PROFILE=enterprise` |

## Per-tenant credentials

Each tenant supplies its own provider API keys, model choices, and budget by
dropping a `config.toml` at `~/.maverick/tenants/<id>/config.toml`. It overlays
the global config (highest precedence) only while that tenant is active:

```toml
# ~/.maverick/tenants/acme/config.toml
[providers.anthropic]
api_key = "${ACME_ANTHROPIC_API_KEY}"   # ${VAR} interpolates from the env

[models]
orchestrator = "anthropic:claude-opus-4-8"

[budget]
max_dollars = 50

# Per-tenant identity provider: in the one-instance-per-tenant model each
# tenant authenticates against its own IdP. Resolved from this overlay while
# the tenant is active, exactly like provider keys.
[auth.oidc]
issuer = "https://acme.example.com"
audience = "maverick-acme"
```

`maverick tenant create <id>` prints this path; the provisioning API returns it
as `config_path`. The same overlay drives a tenant's `[channels.*]` bot
identities and `[auth.oidc]` provider — so credentials, models, budget, channel
bots and IdP are all per-tenant in the one-instance-per-tenant model.

## Plan tiers are enforced

A tenant's plan (`free` / `pro` / `enterprise`, or operator-defined under
`[billing.plans]`) gates real behaviour, not just labels:

- **concurrency** — `max_concurrent_goals` caps a tenant's in-flight goals;
- **channels** — a plan without the `channels` feature is refused at the
  channel door;
- **audit_export** — `maverick audit export --tenant <id>` requires the
  `audit_export` feature.

Enforcement is fail-open at the edges: single-tenant and unprovisioned per-user
tenants are never gated — only a tenant an operator explicitly put on a limited
plan is denied.

The installation's own first workspace (`local`, "My workspace"), which the
dashboard creates for the first owner, is on the built-in `self-hosted` plan:
every feature a plan can gate, including the departments add-on, and no plan
limits. Assign `free`, `pro` or `enterprise` to the tenants you bill.

## Provisioning

```bash
# CLI
maverick tenant create acme --plan enterprise --max-daily-dollars 100
maverick tenant list
maverick tenant suspend acme   # / resume / quota / delete --purge
```

```text
# REST (admin only)
GET/POST           /api/v1/admin/tenants
GET/DELETE         /api/v1/admin/tenants/{id}
POST               /api/v1/admin/tenants/{id}/{suspend,resume,plan,quota}
GET/PUT/DELETE     /api/v1/admin/tenants/{id}/roles[/{principal}]
```

A suspended or over-quota tenant is refused at the channel door before any goal
runs; a tenant at its plan's concurrency ceiling is told to retry.

## Channels are a per-instance boundary

Channels (Slack, Telegram, email, …) are **global listeners** built once at
startup: one bot identity per channel type, per process. Inbound replies route
back to the originating channel — there is **no cross-tenant reply leak** — but
all tenants behind one process share that one bot identity and its allow-lists.

When tenants need **distinct bot identities** (their own Slack workspace bot,
their own inbound email address/webhook), run **one Lightwork instance per
tenant**. The Helm chart (`deploy/helm`) plus the per-tenant config overlay make
this cheap: one release per tenant, each with its own `[channels.*]` and
credentials. `maverick serve` logs an advisory when it detects a multi-tenant
deployment using shared global channels.

For purely API/dashboard-driven tenants (no inbound chat bots), a single
multi-tenant instance is fine.

## Scaling

SQLite is single-writer (one control-plane replica per state volume). Postgres
shares world-model rows and enables database-enforced tenant isolation, but it
does not share every flow, A2A, audit, learning, and policy store. Keep one
dashboard/serve replica and scale remote workers separately — see
[`deploy/postgres/README.md`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/deploy/postgres/README.md). Row-level security
(`MAVERICK_PG_RLS=1`) adds a database-side check of the tenant boundary on
every world-model table that holds a workspace's records; "What row-level security covers" below says
what that includes and what it does not.

### Records saved before workspaces were used

On Postgres every workspace shares the same tables. A record saved while no
workspace was active has no workspace (`tenant_id IS NULL`). In compatibility
mode, which is strict isolation off, **every workspace reads those records**
next to its own. This holds with at-rest encryption on as well: encryption
protects the stored bytes, and the row filter decides who may read a record.
A value sealed for one workspace still cannot be opened by another.

`maverick doctor` and Installation health warn when such records exist and a
workspace exists or is active. To end the sharing:

```
maverick tenant backfill --tenant <id> --dry-run   # how many records?
maverick tenant backfill --tenant <id>             # give them to one workspace
```

Then turn on strict isolation (`MAVERICK_STRICT_TENANT_ISOLATION=1`, or "Hide
records with no workspace" in Settings). Nothing warns on SQLite (one file per
workspace), under strict isolation, or when no such record exists. The doctor
counts goals, facts and their history, conversations, approvals and projects,
the records every workspace reads. The backfill reports more rows, because it
also assigns message markers, receipts and event rows that no other workspace
reads.

What to expect from the backfill:

- **Writes wait while it runs.** It re-seals each encrypted value for the
  workspace it goes to, and no new goal, fact, conversation turn or event can
  be saved until it finishes. Run it in a quiet period, or stop Lightwork
  first. The dry run reports how many encrypted values there are; allow about
  one minute for every 500,000 (100,000 took about 4 seconds on a test
  machine). Reads are not held up.
- **Records the workspace already has stay apart.** A learning record saved
  both without a workspace and in the target workspace under the same key
  keeps the workspace's own; the other is left unchanged and listed by table
  and key, for you to delete. Any other clash stops the backfill and names
  the table and the key.
- **It is all or nothing.** It is one transaction. If Lightwork is busy
  writing for more than 10 seconds, or the database stops it, it says so,
  changes nothing, and can be run again.
- **Run it where the encryption key is.** Use the computer that runs
  Lightwork, with the same encryption settings. If a value cannot be opened,
  it names the table and row and changes nothing. The cause is the wrong key
  on this computer, or a value that was saved for another workspace.
- **Run it before row-level security is on, or as a login that bypasses it.**
  An ordinary login cannot see records without a workspace once the policies
  are in force. The backfill says so and stops.

### Enabling RLS safely (auto-on under enterprise; guided opt-in otherwise)

RLS auto-enables under enterprise mode (`MAVERICK_PROFILE=enterprise`) along with
strict per-tenant reads (`MAVERICK_STRICT_TENANT_ISOLATION`); an explicit
`MAVERICK_PG_RLS=0/1` always wins over the enterprise default. Because its policy
is strict, fail-closed equality (a row is visible/writable only when its
`tenant_id` equals the active tenant), the **enterprise auto-on path runs a boot
preflight that refuses to start** if legacy `tenant_id IS NULL` rows are present
(rather than silently freezing them) — so the sharp edges below must be cleared
first. An operator who sets `MAVERICK_PG_RLS=1` explicitly keeps the fail-closed
install path with no boot refusal (a knowing opt-in). The two sharp edges:

- **Pre-tenancy rows have `tenant_id IS NULL`** and would become invisible *and*
  frozen the moment RLS is forced (`NULL = <tenant>` is never true).
- **Only the table owner** may install the policy; a non-owner app role fails at
  startup instead.

So enabling RLS is a sequenced migration, not a config flip:

```
maverick tenant rls-preflight              # per-table: does this role own it?
                                           # how many legacy NULL-tenant rows?
maverick tenant backfill --tenant <id>     # assign those NULL rows to a tenant
maverick tenant backfill --tenant <id> --dry-run   # preview first
```

Once `rls-preflight` reports **READY** (every table owned by the app role, no
NULL-tenant rows left), set `[world_model] rls = true` (or `MAVERICK_PG_RLS=1`).
The installer's advanced step writes this with the same reminder. RLS is
defense-in-depth: the app-layer `_tenant_scope` predicate already isolates
tenants NULL-tolerantly, so single-tenant and SQLite installs need none of this.

Once RLS is on, the policy hides rows with no tenant from an ordinary login,
so `rls-preflight` counts where they are visible and says how ("counted as"):
as a superuser or `BYPASSRLS` login; on a table with no policy; or as the
table owner, lifting `FORCE` for the count inside a transaction that it rolls
back. Lifting it queues an exclusive lock that other queries on the table wait
behind, so it waits at most 200 ms and reports a busy table as "could not
count: the table was busy"; run it again when Lightwork is quiet. The
dashboard's database check never lifts it and shows such tables as not
counted. A login that does not own the tables and does not bypass RLS cannot
count them: the report says "NOT COUNTED" and is never READY.

The check also lists orphaned rows that no workspace can see: questions or
messages with no task, sign-offs whose approval is gone, and the like. Backfill
cannot assign them, so delete them (or attach them to a record of the right
workspace) before turning RLS on; until then the check is not READY.

#### What row-level security covers

- **Covered:** every world-model table that holds a workspace's records (34
  tables; migration 56 added 18 of them). The 21 tables with their own tenant
  column (`goals`, `facts`, `conversations`, `approvals`,
  `processed_messages`, `projects`, `fact_history`, `erasure_receipts`,
  `approval_audit_outbox`, `attachment_submissions`, `event_goal_admissions`,
  `event_trigger_batches`, `webhook_subscriptions`, `webhook_deliveries`,
  `deadline_alerts`, `encryption_migrations`, `approval_checks` and the four
  learning-store tables `harness_*`) compare it with the workspace. `episodes`
  and `goal_events` carry a copy of their goal's tenant, which database
  triggers stamp from the goal on every write and carry along when the goal
  is reassigned (backfill); a writer cannot set it. The other 11 child tables
  (`messages`, `questions`, `artifacts`, `attachments`, `share_links`,
  `signoffs`, `goal_origins`, `goal_mutation_receipts`, `decision_requests`,
  `approval_signoffs` and `turns`) check that their parent goal, approval or
  conversation belongs to the workspace, by primary key; a new turn must also
  name a goal of the same workspace. The policy is enabled **and forced**, so
  it also applies to the role that owns the tables. A statement with no tenant
  filter cannot read, change or delete another tenant's rows, or rows with no
  tenant, and cannot move a row or add a child row under another tenant's
  parent.
- **Not covered, on purpose:** the deployment-wide tables `halt`,
  `provider_spend`, `provider_cap_receipts`, `provider_operation_attempts`,
  `provider_operation_attempt_backfill`, `rate_events` and
  `schema_migrations`. They hold no workspace's records.
- **Not covered yet:** tables other stores create on first use in the same
  database. `mvk_vectors` (vector memory) and `knowledge_chunks` (the
  knowledge store) hold workspace data and have no row policy; they rely on
  their store's own filters. `governed_records` installs and forces its own
  tenant policy. A test creates these tables, lists every table in the schema,
  and fails when one is in none of these lists.
- **Cost.** Measured on 200,000 goals, 100,000 episodes and 100,000 events.
  The workspace spend total took 47-50 ms with the policies and 42-47 ms
  without them; counting a workspace's events took 17-20 ms (13-14 ms
  without). Saving an event costs about 4 microseconds more. A child table
  that checks its parent costs one index probe per row: reading 50 rows of
  one goal took 0.14 ms instead of 0.08 ms.
- **Upgrading.** Migration 56 runs when the table owner starts Lightwork; a
  login that does not own the tables cannot run it, so start once as the
  owner after upgrading. It adds an empty `tenant_id` column to `goal_events`
  and `episodes` and the triggers that fill it for new rows. Copying each
  existing row's workspace into it costs about 10-13 microseconds a row, so
  only installations that use RLS pay it:
  - **RLS already on (forced).** Migration 56 fills both tables in one
    transaction, with them and `goals` locked for writes. Allow about two
    minutes per 10 million events and episodes, and upgrade in a quiet window.
    It also installs the new policies.
  - **RLS off.** Nothing is rewritten. Turning RLS on later fills the column
    in batches of 10,000 rows, each its own short transaction, before any
    policy that reads it is installed; then it installs every policy.
- **The login matters.** A superuser or a role with `BYPASSRLS` skips every
  policy. Lightwork reports such a login in the readiness details and refuses
  to start with it in enterprise mode. Use a dedicated login that is neither.
- **The policy trusts a transaction setting.** It compares each row with
  `maverick.tenant` (or `maverick.workspace`), which Lightwork sets at the
  start of every transaction. SQL run directly on that connection can set it
  too. RLS is a second check on Lightwork's own queries, not a boundary
  against someone who can run SQL as the application's database role.
  No default path runs a caller's SQL on that connection. The `database`
  tool could, if `DATABASE_URL` or an agent's address named the world
  database, so it refuses an address with the same host, port and database
  as the world DSN. Only the organisation can lift that, with
  `[tools] database_allow_world_database = true` in its own settings or
  `MAVERICK_DATABASE_ALLOW_WORLD_DATABASE=1`; a workspace's settings cannot.
  If you lift it, give the tool a separate read-only login. Every name for
  this computer counts as the same host (`localhost`, any `127.x` address and
  short forms such as `127.1`, `0.0.0.0`, `::1` in any form, its host name,
  its other addresses, a socket path, percent-encoded or not). A service
  definition (`service=` or `PGSERVICE`), in the address or in the world DSN,
  is read from the service files libpq uses (`PGSERVICEFILE` or
  `~/.pg_service.conf`, then the system file); the `PGHOST`, `PGPORT`,
  `PGDATABASE` and `PGUSER` defaults fill in what is still missing. When a
  service cannot be read and the server stays unknown, the tool refuses and
  says it cannot tell whether the address is Lightwork's own database.
  Another DNS name or address for a remote world server is not recognised.

The webhook and deadline-alert tables (`webhook_subscriptions`,
`webhook_deliveries`, `deadline_alerts`) store the workspace id as written
(`slack:U1`), while every `tenant_id` column stores its path-safe form
(`slack%3AU1`). Their policy therefore compares against a second
transaction-local setting, `maverick.workspace`. A version before this one
compared them with `maverick.tenant`, so under RLS a workspace whose id contains
a character outside `A-Z a-z 0-9 . _ -` could not read or add its own webhooks
and deadline alerts. The first start of this version as the table owner replaces
the policy on those three tables; no data changes. Upgrade and restart every
process that uses the database: a process still on the earlier version sees no
rows in those tables until it is upgraded. If the application's database role
does not own those tables, it cannot replace the policy: it still starts, logs
a warning, and keeps the earlier behaviour until Lightwork is started once as
the table owner.
