# Lightwork browser demo

Run Lightwork as a **website** — the dashboard (web UI + REST API) in a browser
— instead of the terminal, for a demonstration instance. All three options
below serve the **same** hardened image (`deploy/docker/Dockerfile`,
unprivileged uid 1000) running `maverick dashboard`; they differ only in
*where* it runs and *how* it's reached.

> The dashboard refuses to serve its admin surface off `localhost` without a
> bearer token, so every option here is **token-gated** — via the
> `Authorization: Bearer <TOKEN>` header. The dashboard does not accept a
> `?token=` query parameter, which would leak the bearer through browser
> history, server logs and the `Referer` header. A browser navigation can't
> set that header, so there is no plain clickable demo link; see each option
> below for how to reach it. Treat the token like a password either way.

---

## Option 1 — Local, one command

Runs on your own machine. The published port binds to host loopback. Use a
current Docker release and an appropriate host firewall.

```bash
cd deploy/demo
cp demo.env.example demo.env        # put your ANTHROPIC_API_KEY in it
./run-demo.sh                       # builds, starts, prints the URL + token
```

`run-demo.sh` generates a token (stored in `.demo-token`, git-ignored), boots
the container, waits for `/livez`, and prints `http://localhost:8765/` plus
the token and a ready-to-use `curl -H "Authorization: Bearer …"` command.
For an actual click-through link on your own machine, put a header-injecting
browser extension (e.g. ModHeader) in front, or use the nginx pattern from
Option 2. Stop with `docker compose -f docker-compose.yml down` (add `-v` to
wipe demo state for a clean slate).

## Option 2 — Hosted HTTPS URL on a VPS

A reachable HTTPS URL, on a VPS behind a TLS-terminating proxy.

```bash
# on the VPS, from the repo root:
MAVERICK_DASHBOARD_TOKEN=$(openssl rand -hex 24) \
  docker compose -f deploy/demo/docker-compose.yml --env-file deploy/demo/demo.env up -d --build
# edit deploy/demo/Caddyfile (set your domain), then:
caddy run --config deploy/demo/Caddyfile
```

`deploy/demo/Caddyfile` only terminates TLS — it does not inject the
`Authorization` header, so `https://demo.example.com/` still needs the
Bearer header (curl/Postman/a header-injecting extension), same as Option 1.
For a proxy that injects the header so viewers get a plain clickable URL,
use
`deploy/reference-architectures/demo-cluster/nginx.conf.template` instead
(it sets `proxy_set_header Authorization "Bearer ${MAVERICK_DASHBOARD_TOKEN}"`)
— treat that link like a password, since anyone who has it is authenticated.

## Option 3 — Managed platform blueprint

Infrastructure-as-code for an isolated instance on a managed platform. Two
blueprints:

- **Render** — `deploy/demo/render.yaml`. In Render: *New → Blueprint*, point at
  this repo. `MAVERICK_DASHBOARD_TOKEN` is generated; set `ANTHROPIC_API_KEY`
  in the service's Environment tab. Demo link: `https://<service>.onrender.com/`
  — authenticate with the token (copied from the Environment tab) via the
  `Authorization: Bearer` header.
- **Fly.io** — `deploy/demo/fly.toml`. From the repo root:
  ```bash
  flyctl launch --copy-config --config deploy/demo/fly.toml --no-deploy
  flyctl secrets set --config deploy/demo/fly.toml \
      ANTHROPIC_API_KEY=your-key-here MAVERICK_DASHBOARD_TOKEN=$(openssl rand -hex 24)
  flyctl deploy --config deploy/demo/fly.toml
  ```
  Demo link: `https://<app>.fly.dev/` — authenticate with the token you set
  via the `Authorization: Bearer` header.

> These blueprints are templates written to each platform's documented schema;
> validate the first deploy against your account (plan names, regions, and
> port-detection can vary by platform tier).

---

## Cost & safety (read before exposing publicly)

Goals run **real** LLM calls billed to your `ANTHROPIC_API_KEY`. Every option
ships conservative guardrails you can tune via env:

| Knob | Default | Effect |
|------|---------|--------|
| `MAVERICK_BUDGET_DOLLARS` | `0.50` | Per-goal USD spend cap |
| `MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN` | `3` | Per-caller goal submissions/min (then HTTP 429) |
| `MAVERICK_DASHBOARD_MAX_GOALS_GLOBAL_PER_MIN` | `10` | Global goal submissions/min |

**Sandbox note:** in this demo configuration agent-generated code runs in the
container's *local* sandbox — the container (unprivileged user, ephemeral
state) is the isolation boundary, which suits a controlled demonstration. For a
hardened, internet-exposed, or multi-tenant deployment, enable a container
sandbox backend and enterprise mode (egress lock, fail-closed consent) — see
`docs/enterprise/deployment-playbook.md` and `docs/enterprise/single-client-deployment.md`.

## Not for demos?

For production/self-host paths (CLI image, VPS+systemd, Helm, GitHub Action),
see the siblings of this directory under `deploy/` and the enterprise docs.
