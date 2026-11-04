# maverick-widget

A single self-contained JavaScript file (`maverick-widget.js` — no
framework, no CDN, no build step) that you drop into any page to get
a floating Lightwork status pill. Clicking it expands a panel with
**active / done / failed** counts and the most recent finished result.

```html
<script src="/widget/maverick-widget.js"
        data-endpoint=""
        data-interval="15000"></script>
```

| attribute | meaning |
|---|---|
| `data-endpoint` | Base URL of the dashboard. Default `""` = same origin (recommended). |
| `data-token` | Optional bearer token — read **Security** below before using. |
| `data-interval` | Poll interval ms (floor 5000). |

## What it calls

The widget is **read-only**: it polls `GET /api/v1/goals?limit=100`, a real
dashboard endpoint (`maverick_dashboard/api.py`, `APIRouter` mounted at
`/api/v1`), and computes the buckets client-side from each goal's `status`:

- **active** = `pending`, `active`
- **done** = `done`
- **failed** = `blocked`, `cancelled` — note: the world model never writes
  a literal `failed` status (see the comment in
  `maverick/world_model.py::search_goals`); `blocked` *is* the failure
  outcome. The widget also counts a literal `failed` defensively in case
  that ever changes.

> The widget derives its counts from the goals list. It does not use the
> dashboard's `/api/v1/glance` endpoint, which serves a fixed-shape status
> payload for small-screen clients (`maverick.glance`).

## Deployment: must be same-origin with the dashboard

The dashboard sets **no CORS headers** (there is no `CORSMiddleware` in
`maverick_dashboard/app.py`), so a browser will block the widget's `fetch`
if the page is served from a different origin than the dashboard. Serve the
widget same-origin, or front both with a reverse proxy that makes it so:

```nginx
# Serve the widget + your page same-origin with the dashboard.
server {
    listen 443 ssl;
    server_name tools.example.com;

    location /widget/ {
        alias /opt/maverick/extensions/widget/;   # maverick-widget.js, demo.html
    }
    location / {
        proxy_pass http://127.0.0.1:8765;         # maverick dashboard
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Host $host;
    }
}
```

## Auth — exactly what the dashboard enforces

From `maverick_dashboard/app.py` (`bearer_auth` middleware, `_is_proxied`,
`_is_same_origin`):

- **Token mode** (`MAVERICK_DASHBOARD_TOKEN` set on the dashboard process):
  *every* request, including GETs, must carry the header
  `Authorization: Bearer <token>` — that is the only header the widget
  sends, and the only form the middleware accepts (`?token=` query auth was
  removed). Compared with `hmac.compare_digest`; anything else gets `401`.
- **No-token mode**: the dashboard serves **loopback peers only**, and any
  request carrying a proxy-forwarding header (`X-Forwarded-For`,
  `X-Forwarded-Host`, `X-Real-IP`, `Forwarded`) is rejected with `401`
  (fail-closed: a proxy in front of a token-less dashboard would otherwise
  expose it). **Consequence: behind any reverse proxy you must set
  `MAVERICK_DASHBOARD_TOKEN`** and either let the proxy inject the header
  (like the demo-cluster blueprint does) or pass `data-token`.
- **CSRF/origin posture**: mutating methods (non-GET/HEAD/OPTIONS) from
  browsers without a bearer are blocked by a same-origin Origin/Referer
  check. The widget never sends a mutating request, so this never triggers
  — but it is why "just open the dashboard cross-site" is not a supported
  deployment.

## Security — read before setting `data-token`

`MAVERICK_DASHBOARD_TOKEN` is the **full control-surface credential**:
the same token authorizes `POST /api/v1/halt`, `POST /api/v1/goals`,
permission toggles, fleet operations — everything. The dashboard has no
read-only token scope. Embedding the token in a page (`data-token`) hands
it to every visitor who can view source. Therefore:

- **Internal same-origin pages, proxy injects the header**: best option —
  the token never reaches the browser (see
  `deploy/reference-architectures/demo-cluster/` for a worked deny-proxy).
- **`data-token` directly in the page**: acceptable only when everyone who
  can load the page is already trusted with full dashboard control.
- **Public pages**: never embed the token; use the demo-cluster pattern
  (nginx injects the bearer upstream *and* strips non-GET methods).

## Trying it locally

`demo.html` embeds the widget with `data-endpoint=""` (same origin). Because
of the CORS posture above, opening it from disk shows the widget in its
"offline" state. To see live data, serve it same-origin with the dashboard
(nginx snippet above), or temporarily run a dev proxy of your choice.

## Tests

- `maverick-widget.js` is syntax-checked with `node --check` and statically
  tested (real endpoint path, auth header shape, no CDN references). The
  tests do not exercise the demo page against a live dashboard.

```bash
# Test lives with the other artifact contract tests (pytest doesn't
# collect extensions/):
python -m pytest packages/maverick-core/tests/test_widget_extension.py -q
```
