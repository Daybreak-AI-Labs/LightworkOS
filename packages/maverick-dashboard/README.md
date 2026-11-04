# maverick-dashboard

The web dashboard and REST API for Lightwork. It is the in-product home for
running and governing agent work: everything a person does after installation
has a journey here, and the same actions are available through the REST API at
`/api/v1`.

What it covers:

- Chat and tasks: start a goal, follow its steps, answer an agent's question,
  stop or resume it, and review the result and the work behind it.
- Approvals: connector changes and other high-risk actions wait here for a
  person's decision, with the exact request shown.
- Agents and specialists: the built-in domain packs, the agent factory, flows
  and schedules.
- Governance, privacy and compliance workbenches, each behind its own setting.
- Settings: providers and models, task limits, permissions and where work
  runs, plus every setting under Settings > All settings.
- Activity: the signed audit log, spend, and the platform's own health.
- The Copilot panel, which acts under the same permissions as the page it is
  opened on.

## Design

- FastAPI with server-rendered Jinja2 templates and plain JavaScript; no build
  step. The shared design system is `maverick_dashboard/static/lightwork.css`.
- Binds to `127.0.0.1` by default. A non-loopback host requires
  `MAVERICK_DASHBOARD_TOKEN` (sent as `Authorization: Bearer <token>`) or a
  configured sign-in method. Query-string tokens are not accepted because they
  leak through the Referer header and access logs.
- Mutating `/api/v1` requests must pass a same-origin check.
- Baseline browser security headers (X-Frame-Options DENY,
  X-Content-Type-Options nosniff, Referrer-Policy same-origin,
  Cross-Origin-Opener-Policy same-origin) are applied to every response.
- `/healthz`, `/livez` and `/readyz` are served without authentication for
  load-balancer probes; their payload is redacted when a token is set.
- State lives in the world model: `~/.maverick/world.db` (SQLite) by default,
  or Postgres when `[world_model] backend = "postgres"`.

The REST API is documented in `docs/api.md` and browsable at `/docs` on a
running dashboard.

## Run

The dashboard is installed by
[Install from source](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/source-install.md).

```bash
maverick-dashboard          # listens on http://127.0.0.1:8765
```

Or via the core CLI:

```bash
lightwork dashboard
```
