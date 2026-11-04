# Operations runbook

When something is wrong, start here. Each section is one symptom with a
checked playbook.

## Endpoints

| Endpoint | Auth | What it tells you |
|---|---|---|
| `GET /livez` | none | Process is alive (TCP accepts). |
| `GET /healthz` | none | Deep checks: DB writable, LLM key present, runner alive. Returns 503 if degraded. |
| `GET /readyz` | none | Traffic admission: all `/healthz` checks plus client binding, required Shield, and agent-trust registry checks. Returns 503 when the process is healthy but not safe to receive work. |
| `GET /metrics` | bearer (when set) | Prometheus text format: goals by status, $ spent, tokens, concurrent goals. |
| `GET /api/v1/spend` | bearer | Total spend + recent episode list. |

`MAVERICK_DASHBOARD_TOKEN` gates `/api/v1/*` and `/metrics`. The three
health endpoints (`livez`, `healthz`, `readyz`) and API-documentation
routes (`openapi.json`, `docs`, `redoc`, `docs/oauth2-redirect`) are
always public so monitoring and API discovery work on a locked-down VPS.

Treat `/healthz` and `/readyz` as different signals. A green `/healthz`
with a 503 `/readyz` means the process and its dependencies are alive,
but a deployment safety precondition is missing; keep the instance out of
service and act on the failed readiness check instead of restarting it.

## "The service is hung"

```sh
# Is it accepting connections?
curl -sS http://127.0.0.1:8765/livez
# {"status":"ok"} → process alive. Continue.
# (no response / timeout) → process dead or wedged. Jump to "process died".

# Are the deep checks green?
curl -sS http://127.0.0.1:8765/healthz | jq
# {"status":"degraded","checks":{"db":"fail: ...","llm_key":"ok",...}}
# → look at the failing check and act on its message.

# How many goals are in flight right now?
curl -sS http://127.0.0.1:8765/metrics | grep maverick_concurrent_goals
# maverick_concurrent_goals 2   ← 2/3 slots used; not maxed.
```

If `/healthz` says `db: fail: ... database is locked`, a long-running
write transaction is blocking. Restart `maverick serve` to release.

## Process died

```sh
# What does systemd say?
systemctl status maverick

# Last 200 lines:
journalctl -u maverick -n 200 --no-pager

# If crash-looping (Restart= triggered too many times), unit enters
# 'failed'. To clear:
systemctl reset-failed maverick
systemctl start maverick
```

The systemd unit (`deploy/vps/maverick.service`) sets
`StartLimitBurst=5` over `StartLimitIntervalSec=300`. After 5 crashes
in 5 minutes the unit enters `failed` rather than respawning forever
and burning API credits.

## Goals stuck in `active` after a crash

This is now handled automatically: on every `maverick serve` and
`maverick dashboard` startup, `reclaim_orphan_goals()` flips rows
from `active`/`pending` to `blocked` with result
`[process restarted mid-run]`.

If you see active goals that *should* be running, check `/metrics`:
`maverick_concurrent_goals` should be > 0. If it's 0 but rows show
`active`, the reclaim hook didn't fire — open an issue.

## API credits burning unexpectedly

```sh
# Total spend over all time:
curl -sS -H "Authorization: Bearer $TOKEN" \
    http://127.0.0.1:8765/api/v1/spend | jq

# Per-goal breakdown (most recent first):
curl -sS -H "Authorization: Bearer $TOKEN" \
    "http://127.0.0.1:8765/api/v1/spend?limit=20" | jq
```

For an explicit task limit, enable task limits in Settings and set
`[budget] max_dollars`, or supply a limit for that invocation. Ordinary tasks
have no generated cap; previously saved numeric choices remain effective until
disabled. [Task limits](task-limits.md) explains the distinction from organization
and principal allowances. Metering still records provider usage.

An administrator can inspect tenants with `maverick tenant list` and configure
an organization's daily allowance with `maverick tenant quota TENANT_ID AMOUNT`
(for example, `maverick tenant quota acme 100`). The Workspaces page exposes the
same allowance. New physical provider attempts check the current allowance and
durable pending holds; merely starting a task allocates no full-task hold.

For unresolved provider charges, open **Workspace recovery → Provider spending**
as a global administrator. Select the exact provider and UTC period, inspect the
reservation, and review final receipt evidence before confirming a correction.
This is an in-app review, not a CLI reset or retry command. See
[provider spending recovery](provider-spending.md) for isolation and repair
requirements. Do not delete accounting files or treat a timeout as zero cost.

Organization holds release only after the cumulative usage ledger acknowledges
known costs. If the process ended before that acknowledgement, the run still
needs restoration and settlement; resolving a provider receipt alone does not
establish that every organization hold was released. Unknown holds do not expire
at midnight. Keep the tenant usage ledger, pending holds, indexed receipt history
and their required-state markers together in backup and recovery.

## Restoring the local application state

The world database path depends on the active client/workspace and any explicit
operator override. A client-bound installation normally uses
`$MAVERICK_HOME/tenants/<client>/world.db`; do not assume that
`~/.maverick/world.db` is the database the customer is using. Run `maverick doctor`
with the service's account, home, configuration and binding, and inventory each
workspace and external store before choosing the recovery scope.

Use the authenticated backup CLI for the bound client's local state. Run these
commands as the service user with the same `MAVERICK_HOME` and client binding.
Provision `MAVERICK_BACKUP_SIGNING_KEY` from the secret manager first; retain
the same 32-byte key independently for the standby. Never generate a different
key when attempting to authenticate an existing archive.

```sh
umask 077
install -d -m 700 "$HOME/maverick-backups"
maverick backup create --out "$HOME/maverick-backups/client.tgz"
maverick backup info "$HOME/maverick-backups/client.tgz"
```

The snapshot uses SQLite's online backup API to include committed WAL data.
Copying one live `world.db` file can miss committed data and does not recover
the other application stores. A single database copy is not an installation
backup.

For recovery, stop all writers first (`maverick serve`, the dashboard and any
service wrapping them). With the standby's actual service identity, home,
configuration, binding and retained key selected:

```sh
maverick backup restore "$HOME/maverick-backups/client.tgz"
```

Restore authenticates and validates the archive, stages it privately, and
journals publication and SQLite sidecars. `--force` can override client/live-world
admission checks; it does not authenticate an unsigned archive, bypass archive
validation or permit a forward-schema restore. A quiet WAL is not proof that
another writer has stopped. Do not use direct file replacement to bypass the
restore safeguards.

The default archive excludes raw encryption and audit-signing `.key` files.
Restore these from separate custody, plus installation configuration, global
account/administration state, additional workspaces and any external stores
through their own recovery procedure. Before returning the service to use,
verify customer records can be decrypted and a representative workflow can
resume with its protected spending and action history intact. Measure recovery
on a separate host; archive integrity alone does not establish that result.

## Postgres backup & disaster recovery

When the world model runs on Postgres (`[world_model] backend = "postgres"` /
`MAVERICK_WORLD_BACKEND=postgres`) the SQLite `.backup` path above does **not**
apply — back up the database itself. The runtime's own `maverick backup`
snapshot covers the single-node SQLite layout; Postgres DR is owned by your
database, the same as any other Postgres-backed service.

Recommended, in order of RPO:

1. **Managed Postgres point-in-time recovery (PITR).** If you run RDS / Cloud
   SQL / Aurora / a managed PG, enable automated backups + PITR. This is the
   lowest-RPO option (seconds–minutes) and needs no Lightwork-specific steps.

2. **Continuous archiving (self-managed).** Enable WAL archiving
   (`archive_mode = on`) + base backups (`pg_basebackup`) for PITR on a
   self-managed cluster.

3. **Logical dumps (portable, higher RPO).** A scheduled `pg_dump` is the
   simplest portable backup:

   ```sh
   # Keep dump contents owner-only, and keep DB credentials out of argv.
   umask 077
   install -d -m 700 "$HOME/.maverick/backups/postgres"

   # Configure connection secrets with PGSERVICE, ~/.pgpass, peer auth, or your
   # secret manager instead of embedding passwords in the command line.
   pg_dump --format=custom --no-owner \
     --dbname=service=maverick \
     --file="$HOME/.maverick/backups/postgres/maverick-pg-$(date +%Y%m%d).dump"

   # restore into a fresh database/service target:
   pg_restore --no-owner --dbname=service=maverick_restore \
     "$HOME/.maverick/backups/postgres/maverick-pg-YYYYMMDD.dump"
   ```

Notes:

- **Encryption at rest:** with `MAVERICK_ENCRYPT_AT_REST=1`, sensitive columns
  are AES-256-GCM ciphertext in the dump too, so a `pg_dump` does not expose
  plaintext — but the dump is only restorable with the **same at-rest key**
  (`~/.maverick/keys/at_rest.key`). Back up that key separately and securely;
  losing it makes sealed columns unrecoverable.
- **Schema migrations are forward-only and idempotent**, applied on first
  connect. Restoring an older dump and starting a newer Lightwork re-applies any
  pending migrations automatically (see `world_model_backends/postgres.py`).
- **Database HA:** managed Postgres can fail over the shared world model. The
  Lightwork dashboard/serve control plane must still run as one replica because
  other durable stores remain file-backed; replace that replica against the
  same persistent data root instead of running active-active control-plane pods.
  The single-node `maverick backup` cold-standby model is for the SQLite default.
- **Single-writer enforcement:** on startup the control plane takes an exclusive advisory lock on `control-plane.lock` in its
  data root and holds it for the process lifetime; a second process refuses to
  start and reports the pid, host and uptime from the atomically published
  `control-plane-holder.json` diagnostic record. This record is observability;
  the OS lock remains the authority. Separating them also keeps diagnostics
  readable on Windows, where byte-range locks deny reads of the locked byte.
  The lock is released by the kernel when the holder exits, so a `Recreate`
  rollout hands over cleanly and there is no stale lock to clear. `/readyz`
  reports the posture
  under `replica_safety`. If the data root sits on a filesystem whose advisory
  locks are a no-op (some NFS and overlay mounts), startup **fails closed**
  rather than assume exclusivity — move the volume, or set
  `MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES=1` (equivalently
  `[deployment] allow_multiple_control_planes = true`) if you have guaranteed
  single-writer access another way. The override is reported on `/readyz` as
  `unenforced`, never silently honoured.

## Learning-state operations

The learning loops persist state under `~/.maverick/` (reflexions, dreams/,
learned-skills/, *_stats.json). Operational handles:

- **Schedule**: `maverick dream` from cron/systemd (nightly is typical). Each
  CLI run snapshots every learned store first.
- **Inspect before it acts**: `maverick dream --dry-run` reports exact
  would-be changes without writing.
- **Roll back**: `maverick dream --list-snapshots` then
  `maverick dream --rollback latest|<name>` restores all learned stores
  wholesale (including removing skills learned after the snapshot).
- **Detect regressions**: `maverick hindsight --strict` exits non-zero if the
  forgetting loops cost coverage on past goals — suitable as a CI/cron gate.
- **Audit**: every dream cycle writes a `learning_update` row to the signed
  audit log; `maverick audit verify` covers learned state like tool calls.
- **Tenant note**: with an active tenant, all learned stores live under that
  tenant's data dir — back up per tenant.

## Retention / garbage collection

Conversations + goal_events accumulate forever by default. Manual:

```sh
maverick gc --days 90 --events-days 30
```

Scheduled (systemd timer, recommended on VPS):

```ini
# /etc/systemd/system/maverick-gc.timer
[Unit]
Description=Lightwork weekly garbage collection

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/maverick-gc.service
[Unit]
Description=Lightwork GC
After=maverick.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/maverick gc --yes
User=maverick
```

`systemctl enable --now maverick-gc.timer`.

## Rotating API keys without downtime

```sh
# Edit the new key in:
sudo -u maverick vim ~maverick/.maverick/.env
# (chmod 600 is enforced by the installer.)

# Hot reload:
systemctl reload maverick
# If the systemd unit doesn't support reload, restart:
systemctl restart maverick
```

## Logs

Plain text by default. Set `MAVERICK_LOG_FORMAT=json` for structured
output suitable for Loki / CloudWatch / Datadog:

```sh
MAVERICK_LOG_FORMAT=json MAVERICK_LOG_LEVEL=DEBUG maverick serve
```

Every log line emitted during a goal run carries `goal_id` and
`conversation_id` (and `channel` when set), so you can grep:

```sh
journalctl -u maverick --since "1 hour ago" -o json \
  | jq 'select(.MESSAGE | fromjson? | .goal_id == 42)'
```

## Setting up `/metrics` scrape

Prometheus config:

```yaml
scrape_configs:
  - job_name: maverick
    metrics_path: /metrics
    bearer_token: <MAVERICK_DASHBOARD_TOKEN>
    static_configs:
      - targets: ["maverick.example.com:8765"]
```

Useful queries:

- `rate(maverick_goals_total{status="done"}[5m])` — completion rate
- `maverick_concurrent_goals / maverick_max_concurrent_goals` —
  saturation
- `increase(maverick_cost_dollars_total[1h])` — spend rate
