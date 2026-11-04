# A2A (Agent2Agent)

Lightwork uses the [A2A 0.3 JSON-RPC contract](https://a2a-protocol.org/v0.3.0/specification/), so other agents can
**discover** this instance and **delegate** long-horizon goals to it. Two
halves:

- **Discovery** — an Agent Card served at `/.well-known/agent-card.json`.
- **Tasks** — a JSON-RPC endpoint at `/a2a/v1` that runs goals and reports
  progress.

Both mount on the dashboard server (`maverick dashboard`, default
`http://127.0.0.1:8765`).

## Enabling

A2A is **off by default**. An administrator can enable **Let other agents send
tasks here** in **All settings > Security**, then restart the service through
the product's service controls. When off, neither the discovery card nor the
task endpoint is registered. The installer also offers this choice.

## Auth

The task endpoint spends real provider budget and **requires an access key by
default**. Prefer an individual key issued through **External agents**. A
shared key can be saved, sealed, in **All settings > Security > Requests from
other agents > Password other agents must send**. Existing deployment
overrides are shown on that page and take precedence.

Callers send `Authorization: Bearer <key>`. The discovery card describes
current native authentication, including explicitly configured anonymous
admission; it never publishes a key. Anonymous admission is off by default.

The Agent Card itself (discovery) is public, like any A2A card.

See also: agents enrolled through the
[bring-your-own-agent gateway](external-agents.md) can hold a per-caller
`a2a` credential (minted from the **/external-agents** dashboard page) that
resolves them to principal `agent:<id>` under the Agent Trust Plane — per-agent
admission and ceilings instead of the one shared surface token.

## Budget caps

Client-supplied budget is always clamped to operator ceilings, so a remote
caller can't run up your provider bill:

| Env var | Default | Caps |
| --- | --- | --- |
| `MAVERICK_A2A_MAX_DOLLARS` | `5.0` | spend per task |
| `MAVERICK_A2A_MAX_WALL_SECONDS` | `3600` | wall-clock per task |
| `MAVERICK_A2A_MAX_DEPTH` | `3` | sub-agent recursion depth |

Every prompt is also screened by the [safety shield](safety.md) when it's
installed (fail-open if not).

## Idempotency and restart safety

`message.messageId` is required and is the caller's idempotency key. Lightwork
scopes it to the active tenant and authenticated principal, then claims it in a
private tenant-local SQLite ledger **before** starting the goal. A retry with
the same content returns the original terminal Task, including after a process
restart; reuse with different content is rejected. Prompt/result snapshots
honor Lightwork's at-rest encryption policy (including per-tenant keys).

If a worker disappears after claiming an id but before durably settling the
result, another worker returns server-busy with an explicit **outcome
indeterminate** refusal. It never guesses that the goal is safe to run again.
Reconcile any external effects before submitting that work under a fresh id.

The retained-result budget is bounded. Old terminal result bodies may become
no-replay tombstones, but their ids remain consumed, so memory pressure cannot
silently turn an old request into a second execution.

## Base URL

The card advertises `…/a2a/v1` as the task URL. Set **Address other agents use**
in **All settings > Security > Requests from other agents** to the public
address of this installation, including its path prefix if applicable. This
changes the advertised address; it does not create external hosting or prove
that another company can reach it.

## Methods

All requests are JSON-RPC 2.0 `POST`ed to `/a2a/v1`.

### `message/send`

Run a goal to completion and return the final **Task**.

```json
{
  "jsonrpc": "2.0", "id": 1, "method": "message/send",
  "params": {
    "message": {
      "role": "user",
      "parts": [{"kind": "text", "text": "summarize the latest CPython release notes"}],
      "messageId": "9229e770-767c-417b-a0b0-f0741243c589"
    }
  }
}
```

Result (abridged):

```json
{
  "jsonrpc": "2.0", "id": 1,
  "result": {
    "id": "363422be-…", "contextId": "c295ea44-…", "kind": "task",
    "status": {"state": "completed", "timestamp": "2026-05-31T…"},
    "artifacts": [{"artifactId": "…", "name": "result",
                   "parts": [{"kind": "text", "text": "…"}]}],
    "history": [{"role": "user", "parts": [{"kind": "text", "text": "…"}]}],
    "metadata": {"statusHistory": [
      {"state": "submitted", "timestamp": "…"},
      {"state": "working",   "timestamp": "…"},
      {"state": "completed", "timestamp": "…"}
    ]}
  }
}
```

`status.state` is one of `submitted`, `working`, `completed`, `failed`,
`canceled`, `rejected`. The full transition timeline is under
`metadata.statusHistory`.

### `message/stream`

Same inputs, but the response is an **SSE** stream (`Content-Type:
text/event-stream`). Each event's `data:` is a JSON-RPC response wrapping
one of: the initial **Task**, a **`status-update`**, or an
**`artifact-update`**. The terminal status-update carries `"final":
true`.

```
data: {"jsonrpc":"2.0","id":1,"result":{"kind":"task","status":{"state":"submitted"},…}}

data: {"jsonrpc":"2.0","id":1,"result":{"kind":"status-update","status":{"state":"working"},"final":false,…}}

data: {"jsonrpc":"2.0","id":1,"result":{"kind":"artifact-update","artifact":{…},"lastChunk":true,…}}

data: {"jsonrpc":"2.0","id":1,"result":{"kind":"status-update","status":{"state":"completed"},"final":true,…}}
```

### `tasks/get` · `tasks/cancel`

```json
{"jsonrpc": "2.0", "id": 1, "method": "tasks/get",    "params": {"id": "<task-id>"}}
{"jsonrpc": "2.0", "id": 1, "method": "tasks/cancel", "params": {"id": "<task-id>"}}
```

`tasks/get` returns the Task (including `metadata.statusHistory`).
`tasks/cancel` is best-effort: a task that hasn't finished is marked
`canceled` and its result discarded, but an already in-flight goal isn't
force-killed mid-step.

### Push notifications

Register a webhook and Lightwork `POST`s the Task to it when the task
reaches a terminal state:

```json
{
  "jsonrpc": "2.0", "id": 1, "method": "tasks/pushNotificationConfig/set",
  "params": {
    "taskId": "<task-id>",
    "pushNotificationConfig": {
      "url": "https://client.example/webhook",
      "token": "secure-client-token"
    }
  }
}
```

The delivery includes `Authorization: Bearer <token>` when a `token` is
configured. Read it back with `tasks/pushNotificationConfig/get`.

## Capabilities

The Agent Card advertises what's backed:

```json
"capabilities": {
  "streaming": true,
  "pushNotifications": true,
  "stateTransitionHistory": true
}
```
