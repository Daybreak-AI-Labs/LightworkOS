# Lightwork Helm chart

Production-oriented chart for the Lightwork dashboard (web UI + API + webhooks).

No container image is published yet. Build one from a clone of the repository
and make it available to your cluster:

```bash
docker build -f deploy/docker/Dockerfile -t <registry>/lightwork:<tag> .
docker push <registry>/lightwork:<tag>
# For a local cluster, load the image instead of pushing it:
#   kind load docker-image <registry>/lightwork:<tag>
#   minikube image load <registry>/lightwork:<tag>
```

Then install the chart with that image:

```bash
# Hosted-provider pilot (SQLite, single replica, standard profile).
# Use enterprise profile with an explicitly allowed/self-hosted provider instead
# when the enterprise data boundary is required.
helm install maverick ./deploy/helm/maverick \
  --set image.repository=<registry>/lightwork \
  --set image.tag=<tag> \
  --set enterprise.profile=standard \
  --set-string secret.data.ANTHROPIC_API_KEY=sk-ant-... \
  --set-string secret.data.MAVERICK_DASHBOARD_TOKEN=$(openssl rand -hex 32)
```

The image runs as the unprivileged `maverick` user (uid/gid 1000); the chart
sets a restricted-PSS `securityContext` and an `fsGroup` so the state PVC is
writable.

## Postgres and scaling

The default world-model backend is **SQLite on a ReadWriteOnce volume**. Move
the world model to Postgres for managed database HA, pooling, and DB-enforced
tenant isolation:

```bash
helm install maverick ./deploy/helm/maverick \
  --set image.repository=<registry>/lightwork \
  --set image.tag=<tag> \
  --set enterprise.profile=standard \
  --set worldModel.backend=postgres \
  --set worldModel.postgres.rls=true \
  --set-string secret.data.MAVERICK_PG_DSN=postgres://maverick:***@host:5432/maverick \
  --set-string secret.data.ANTHROPIC_API_KEY=sk-ant-...
```

Keep `replicaCount=1` and `autoscaling.enabled=false`. Postgres centralizes the
world model, but workflow releases/runs, A2A durable task claims, audit and
learning ledgers, and tenant-local policy state still live in the mounted data
root. Multiple dashboard/serve pods would split approval and idempotency
authority. The chart fails closed on that topology; scale remote goal workers
separately until every control-plane store has a shared transactional backend.

The state PVC is mandatory with either backend and must mount at
`/home/maverick/.maverick`. Disabling it or redirecting `MAVERICK_HOME` elsewhere
is rejected during rendering. Do not place state-path overrides in the Secret:
it is for credentials, and Helm cannot inspect an externally supplied Secret.
The selected vendor-onboarding path and its backup/restore procedure are in
[`docs/vendor-onboarding.md`](../../docs/vendor-onboarding.md). Restoring the
database alone cannot restore approval, reconciliation or learned-flow state.

The chart guard is build-time, so it only covers installs that go through Helm.
The control plane also enforces this at runtime: it takes an exclusive lock on
its data root at startup and a second process refuses to serve, naming the
holder. That is what protects a hand-edited `kubectl apply`, a
`docker compose up --scale`, or two processes on one host. `/readyz` reports the
posture under `replica_safety`.

See [`deploy/postgres/README.md`](../postgres/README.md) for provisioning the
database, row-level-security, pooling, and backups.

## Values

See [`maverick/values.yaml`](maverick/values.yaml) for the full list. Common
overrides: `image.*`, `persistence.size`, `resources`, `ingress.*`,
`env` (plain), `secret.data` (sensitive), `worldModel.backend`.

## Validate before applying

```bash
helm lint ./deploy/helm/maverick
helm template maverick ./deploy/helm/maverick | kubectl apply --dry-run=client -f -
```
