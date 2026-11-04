# Lightwork operations runbook

Quick triage for the alerts in `prometheus-rules.yaml`. Pair with
`docs/operations.md` (the full operator playbook).

## Health surfaces

| Probe | Meaning |
|-------|---------|
| `GET /livez` | process accepts TCP (liveness) |
| `GET /healthz` | deep check: DB writable, provider key present, runner alive — 503 when degraded |
| `GET /readyz` | readiness: the `/healthz` checks PLUS deep checks (client binding, shield-required, agent-trust registry) — 503 when not ready to serve |
| `GET /metrics` | Prometheus series (bearer-gated when a dashboard token is set) |

## Alert: MaverickDown

1. `kubectl get pods -l app.kubernetes.io/name=maverick` — crashloop? OOMKilled?
2. `kubectl logs deploy/<release>-maverick --tail=200` (logs are JSON when
   `MAVERICK_LOG_FORMAT=json`; each goal line carries `goal_id`/`conversation_id`).
3. Hit `/healthz` from inside the cluster. A 503 signals degradation; use the
   authenticated administrator endpoint `/api/v1/admin/system/probe-details`
   to inspect the failing checks.
4. If OOMKilled, raise `resources.limits.memory` (chart values).

## Alert: MaverickConcurrencySaturated

- Expected under sustained load. `maverick_concurrent_goals` is the global
  in-flight gauge; the cap is `MAVERICK_MAX_CONCURRENT_GOALS`.
- A single tenant should NOT be able to starve others — per-tenant ceilings come
  from each tenant's plan (`max_concurrent_goals`). If one tenant is hot, check
  its plan/quota rather than raising the global cap.
- Do not add dashboard/serve replicas: Postgres shares the world model, but not
  every durable control-plane store. To add goal-processing capacity, move the
  world model to Postgres and scale remote workers while keeping exactly one
  control-plane replica. See `deploy/postgres/README.md`.

## Alert: MaverickSpendSpike

1. `maverick billing invoice <tenant>` / check `maverick_cost_dollars_total` by
   tenant to find the source.
2. Tighten caps: global `[budget] max_dollars`, or per-tenant
   `maverick tenant quota <id> <dollars/day>`.
3. A runaway loop usually shows as high `maverick_tokens_total` with few
   `maverick_goals_total{status="done"}` — inspect recent goals.

## Alert: MaverickGoalFailureRate

1. Provider outage? Check the authenticated probe details and provider status.
2. Shield over-blocking? Failures with "Output blocked" in logs.
3. A bad recent deploy? Correlate with rollout time; `helm rollback` if needed.

## Upgrades

- Migrations are forward-only. A pre-existing `world.db` is snapshotted to
  `<db>.pre-migration-v<N>.bak` before upgrade (opt out:
  `[world_model] pre_migration_backup = false`). To roll back a bad migration,
  stop the process and restore that file.
- Online-safe migrations only are allowed through CI
  (`python -m maverick.schema_migrations --ci`), so a rolling upgrade should not
  require downtime — but take a DB backup before major version jumps.

## Tenant lifecycle

- Provision: `maverick tenant create <id> --plan <free|pro|enterprise>`.
- Per-tenant credentials/models: drop a `config.toml` at
  `~/.maverick/tenants/<id>/config.toml`.
- Export (GDPR portability): `maverick client export`.
- Erase: `maverick tenant delete <id> --purge`.
