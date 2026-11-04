# demo-cluster — public read-only demo

Blueprint for a public, **read-only** Lightwork demo: seeded finished runs,
the real dashboard process, and an nginx path-allowlist proxy as the only
exposed surface. Ships as both `docker-compose.yml` and `k8s.yaml` (same
three-part shape).

```
 visitor ──► nginx :8080 ── /demo only ──► dashboard :8765 (token-protected)
             │             injects Authorization: ▲
             │             Bearer $MAVERICK_DASHBOARD_TOKEN
             ├─ / → 302 /demo                   │ state volume /home/maverick/.maverick
             ├─ /healthz → dashboard health     │
             └─ every other path → 404          │
                                        seed_demo.py (one-shot for owner=demo,
                                        real world-model API, finished goals)
```

## Run it

```bash
MAVERICK_DASHBOARD_TOKEN=$(openssl rand -hex 32) \
  docker compose -f deploy/reference-architectures/demo-cluster/docker-compose.yml up -d
# open http://localhost:8080
```

Kubernetes: see the header comment in `k8s.yaml` (secret + seed configmap +
apply).

## Why the deny-proxy is load-bearing

**The dashboard has no global read-only flag.** Setting
`MAVERICK_DASHBOARD_TOKEN` alone does NOT make a deployment read-only — the
token authorizes *everything*. The mutating surface that must never be
publicly reachable (all POST/DELETE; from `maverick_dashboard/api.py` and
`app.py` route decorators):

- goals: `POST /api/v1/goals` (spends real provider money),
  `POST /api/v1/goals/{id}/answer|cancel|resume`, attachment upload,
  annotations, pins, views, gallery
- control surface: `POST/DELETE /api/v1/halt` (killswitch!),
  `POST /api/v1/permissions/tools/{name}/disable|enable`,
  `POST /api/v1/approvals/{id}/approve|deny|claim|release`,
  `POST /api/v1/cache/purge`
- fleets: `POST /api/v1/fleets`, `POST /api/v1/fleets/{name}/run`,
  `DELETE /api/v1/fleets/{name}`
- skills/facts: `POST /api/v1/skills`, `POST /api/v1/catalog/skills/install`,
  `DELETE /api/v1/skills/{name}`, `POST /api/v1/facts`,
  `DELETE /api/v1/generated-tools/{name}`, `POST /api/v1/skills/validate`
- chat + webhooks: `POST /chat/send`, `POST /webhook/start`,
  `POST /webhook/{linear,jira,github,gitlab}` — note the webhooks are
  **exempt from bearer auth** by design (they carry their own HMAC, see
  `_AUTH_EXEMPT` in `app.py`), so the proxy is the only thing standing
  between them and the internet here.

The nginx config (`nginx.conf.template`) therefore **does not** proxy the
authenticated dashboard by method alone. Authenticated GET endpoints include
run history, facts, spend, audit logs, security posture, plugin/MCP/tool
configuration, permissions, approvals, and compliance exports; a method-only
filter would publish that state to every visitor. Instead the public proxy is
path-allowlisted:

- `GET/HEAD /` returns `302 /demo`.
- `GET/HEAD /demo` is the only public page that receives the injected bearer.
  The route renders a redacted, standalone snapshot of goals owned by the
  seeded `demo` principal only; it does not use the full dashboard shell and
  does not expose facts, spend, audit, configuration, permissions, approvals,
  or compliance data.
- `GET/HEAD /healthz` is allowed for load balancers.
- Every other path, including `/api/*`, `/api/v1/*`, `/chat`, `/goals`,
  `/audit`, `/permissions`, and other dashboard pages, returns 404 at nginx.
- Non-GET/HEAD requests to the allowed upstream paths are rejected at nginx
  with `limit_except GET HEAD { deny all; }`.

`proxy_set_header Authorization ...` *replaces* any client-sent Authorization
header on the allowlisted upstream locations, so visitors can neither learn nor
override the token.

Defense in depth: the dashboard container publishes no host port (compose) /
binds loopback inside the pod (k8s), so even a proxy misconfiguration does not
expose it directly. Do not add public proxy paths unless the corresponding
dashboard route is explicitly designed to redact public-demo data.

## What the demo data is

`seed_demo.py` runs once at start (compose one-shot service / k8s init
container) inside the maverick image and writes 6 finished goals for owner
`demo` — 4 `done`, 1 `blocked`, 1 `cancelled` — through the real
`maverick.world_model.WorldModel` API (`create_goal` + `set_goal_status`).
No live agents run in the demo, so nothing is seeded `active` (the
dashboard reclaims orphaned active goals on startup) and no provider API
key is needed or configured.

## Operations — maintainer acts

- **DNS + TLS are not in this blueprint.** The templates use the example
  hostname `demo.maverick.dev` (nginx `server_name` in `nginx.conf.template`
  and `k8s.yaml`); replace it with your own hostname, point its DNS record at
  your host/LoadBalancer and terminate TLS at your edge (compose:
  a TLS proxy in front of :8080; k8s: Ingress/Gateway + cert-manager). Do
  not serve the demo over plain HTTP to the public internet.
- Resource limits are set on every service/container; restart policy is
  `unless-stopped` (compose) / Deployment-managed (k8s), single replica
  (SQLite single-writer, same rule as the kubernetes reference arch).
- Rotation: change the token by restarting with a new
  `MAVERICK_DASHBOARD_TOKEN`; nothing else holds it.
- Re-seeding: `seed_demo.py` is idempotent for the public demo owner (skips
  when owner `demo` already has goals). Non-demo goals in a reused volume do
  not suppress seeding and are not shown by `/demo`; wipe the `demo-state`
  volume to start completely fresh.

## Verification scope

Contract-tested statically in
`packages/maverick-core/tests/test_demo_cluster.py` (compose/k8s/nginx
invariants, seed script compiles and uses the real API, no baked secrets) —
same pattern as the other reference architectures. The test suite does
**not** stand the blueprint up end to end; the first `docker compose up`
against a built image is the smoke test.
