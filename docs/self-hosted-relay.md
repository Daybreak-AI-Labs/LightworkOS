# Self-hosted relay reference

A self-hosted relay that sits between Lightwork and an external device or
client, fronts its inbound requests and applies the **ack-then-run** split:
quick questions are answered inside the caller's deadline; long tasks are
acknowledged immediately, run in the background, and delivered to a secondary
channel when done.

The relay ships as framework-agnostic logic (`maverick.relay_reference`) that
you run **as a small local / edge service** or **as a Worker**. Nothing is
hosted for you, and no paid edge is required.

## Why a relay at all

An external client, such as a voice assistant, a wearable or a chat
integration, often waits only a short, fixed time for a reply (the default here
is 30 seconds). Inside that budget you can answer a fact or a short chat. You
cannot write an article, do research, or deploy something. The relay is the
piece that decides which is which and routes accordingly:

- **Quick query** → proxied synchronously to the agent and answered within the
  deadline.
- **Long task** → instant ack ("Got it! result will be sent to Telegram"),
  forwarded to the existing inbound `POST /webhook/start`, with the full result
  delivered later to a secondary channel.

The quick-vs-ack-then-run boundary **is the point**: it is where long-horizon
work meets a client that cannot wait for it.

## What the reference gives you

`packages/maverick-core/maverick/relay_reference.py` is pure logic with injected
transport, so it unit-tests with no server and no network:

| Piece | Role |
|---|---|
| `classify_request(text, config)` | QUICK vs ACK_THEN_RUN by a configurable regex |
| `RelayConfig` | deadline, long-task pattern, `start_url`, secondary channel, outbound HMAC secret, inbound relay auth token |
| `Relay` | orchestrator; takes injected `sync_handler`, `starter`, `deliver` |
| `build_start_request(...)` | body + signed headers for the forward to `/webhook/start` |
| `sign_body(...)` | HMAC-SHA256 matching `maverick.webhooks` so the receiver verifies it |

You supply three transport seams:

- **`sync_handler(text) -> str`** — drive the agent for a quick query. The relay
  races it against `deadline_seconds` and downgrades to ack-then-run if it
  overruns or raises (the caller always gets a reply).
- **`starter(start_url, payload, *, secret) -> dict`** — POST the task to the
  existing inbound `POST /webhook/start`. Return a handle (`{"run_id": ...}`).
- **`deliver(channel, result, *, context)`** — push a finished result to the
  secondary channel. In production this is `maverick.webhooks.fire` → Telegram.

The relay never does IO itself, so the same core runs unchanged in a Worker or a
local process — only the seams differ.

## Run it as a local service

A minimal FastAPI mount next to the existing dashboard routes:

```python
import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from maverick.relay_reference import Relay, RelayConfig, build_start_request
from maverick import webhooks

config = RelayConfig(
    deadline_seconds=30.0,
    start_url="http://localhost:8080/webhook/start",
    secondary_channel="telegram",
    hmac_secret="...",  # matches MAVERICK_INBOUND_WEBHOOK_SECRET on the receiver
    inbound_auth_token="...",  # separate bearer token required from the device or client
)

def sync_handler(text: str) -> str:
    # Drive the agent synchronously for a quick query. Lightwork ships no
    # quick-answer helper; plug in your own call into the kernel here.
    return my_quick_answer(text)

def starter(start_url, payload, *, secret=None):
    body, headers = build_start_request(payload, config)
    resp = httpx.post(start_url, content=body, headers=headers, timeout=5.0)
    resp.raise_for_status()
    return resp.json()

def deliver(channel, result, *, context=None):
    # Long-task results ride the existing outbound webhooks → secondary channel.
    webhooks.fire("relay_result", {"channel": channel, "text": result, **(context or {})})

relay = Relay(config, sync_handler=sync_handler, starter=starter, deliver=deliver)

app = FastAPI()

@app.post("/relay")
async def relay_endpoint(req: Request, authorization: str | None = Header(default=None)):
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not relay.verify_inbound_token(token):
        raise HTTPException(status_code=401, detail="unauthorized relay request")

    body = await req.json()
    resp = relay.handle(body["text"], context={"source": "device"}, auth_token=token)
    return {"reply": resp.immediate, "kind": resp.kind.value, "started": resp.started}
```

Run it with any ASGI server (`uvicorn yourmodule:app`), behind your own TLS,
and require callers to send `Authorization: Bearer <inbound_auth_token>`. The
inbound bearer token is deliberately separate from the outbound webhook signing
secret so an exposed relay cannot be used as a confused deputy. It points at the Lightwork instance's `POST /webhook/start`; nothing is hosted by us.

## Run it as a Cloudflare Worker

The same decision logic, ported to the Worker fetch handler. Store a separate
`RELAY_INBOUND_TOKEN` secret in the Worker environment and reject requests that
do not present it. The Worker holds no
agent — it classifies, acks, and forwards to your self-hosted Lightwork's
`POST /webhook/start`, then lets the run deliver to the secondary channel.

```js
// worker.js — mirror of classify_request + the ack-then-run split.
const LONG_TASK = /\b(write|build|create|research|deploy|refactor|generate|analy[sz]e|implement)\b/i;

export default {
  async fetch(request, env) {
    const auth = request.headers.get("Authorization") || "";
    if (auth !== `Bearer ${env.RELAY_INBOUND_TOKEN}`) {
      return new Response(JSON.stringify({ error: "unauthorized relay request" }), { status: 401 });
    }

    const { text } = await request.json();
    const isLong = text && LONG_TASK.test(text);

    if (!isLong) {
      // Quick: proxy synchronously to the agent gateway within the deadline.
      const r = await fetch(env.AGENT_QUICK_URL, {
        method: "POST",
        body: JSON.stringify({ text }),
      });
      return new Response(JSON.stringify({ reply: await r.text(), kind: "quick" }));
    }

    // Long: ack now, forward to /webhook/start, let the run deliver to Telegram.
    const payload = JSON.stringify({ goal: text, deliver_to: "telegram", source: "device" });
    // Fire-and-forget so the ack returns inside the caller's deadline.
    request.waitUntil?.(
      fetch(env.START_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
      })
    );
    return new Response(JSON.stringify({
      reply: "Got it! Working on it — the result will be sent to Telegram.",
      kind: "ack_then_run",
    }));
  },
};
```

Keep the Worker's regex in sync with `RelayConfig.long_task_pattern`
(`maverick.relay_reference.DEFAULT_LONG_TASK_PATTERN`) so both deployment shapes
classify identically. The Worker is optional convenience — the local service is
the no-hosted-dependency default.

## Signing the forward

When `RelayConfig.hmac_secret` is set, `build_start_request` attaches
`X-Lightwork-Signature` and `X-Lightwork-Timestamp`, plus identical
`X-Maverick-*` compatibility headers, using the same HMAC-SHA256
construction as `maverick.webhooks`, so the existing inbound `/webhook/start`
receiver verifies the relay's forward. Set the relay's HMAC key to the distinct
`MAVERICK_INBOUND_WEBHOOK_SECRET` configured on the receiving server.

## Fitting it to your client

The relay core does not depend on any particular device or client. Set
`RelayConfig.deadline_seconds` to the reply deadline your client actually
enforces, and shape quick answers to what it can display; both come from that
client's own documentation, not from this reference.
