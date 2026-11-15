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
(`MAVERICK_PG_RLS=1`) enforces the tenant boundary in the database itself.

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
