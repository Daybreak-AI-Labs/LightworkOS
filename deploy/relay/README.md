# Self-hosted relay

A thin, dependency-free edge service that accepts a simple inbound POST and
forwards it as a properly HMAC-signed request to a Lightwork dashboard's
`/webhook/start`. Run it on your own box/VPS/edge instead of depending on a
hosted cloud function — the self-hostable counterpart to a hosted bridge (e.g.
one in front of a wearable device).

```bash
export MAVERICK_RELAY_SECRET=...        # matches the dashboard's [webhooks] secret
export MAVERICK_RELAY_TOKEN=...         # required bearer token for callers
export MAVERICK_RELAY_TARGET=http://127.0.0.1:8765
python deploy/relay/relay.py            # listens on 127.0.0.1:8799 by default

curl -s localhost:8799/relay \
  -H 'authorization: Bearer ...' \
  -H 'content-type: application/json' \
  -d '{"title":"summarize today's incidents","budget":5.0}'
# -> {"goal_id": 123}
```

Env: `MAVERICK_RELAY_SECRET` (required), `MAVERICK_RELAY_TOKEN` (required
bearer the caller must present), `MAVERICK_RELAY_TARGET`
(default `http://127.0.0.1:8765`), `MAVERICK_RELAY_PORT` (default `8799`),
and `MAVERICK_RELAY_HOST` (default `127.0.0.1`; set explicitly if a reverse
proxy or firewall should expose it on another interface).

It signs exactly the way `maverick.webhooks` verifies (timestamp-bound
HMAC-SHA256), so forwarded requests pass the dashboard's replay-defended check —
verified by `tests/test_relay_signature.py`. Stdlib only; keep the relay
behind a trusted reverse proxy/firewall and terminate TLS before any public
exposure.
