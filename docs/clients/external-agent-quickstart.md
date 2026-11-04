# External agent quickstart (any runtime)

Bring an agent that runs on **any** other stack — an OpenAI tool-loop,
LangChain, a scheduled job, a home-grown runtime — under Lightwork
governance through the [external-agent gateway](../external-agents.md).
The screen-only pattern is **screen-then-act, report-after**. Its approval is
advisory because the external runtime performs the effect itself. Use
`POST /api/v1/external/execute` (and its commit endpoint for parked writes)
when Lightwork must enforce the effect:

1. **Screen** every consequential action *before* taking it —
   `POST /api/v1/external/screen` applies the enrolled ceilings (tools,
   risk, budget), Shield input scanning, and the approval floor.
2. **Act** only on `allowed: true`. A `requires_approval` verdict parks a
   real approval that a human decides in the dashboard queue while you
   poll `GET /api/v1/external/approvals/{id}`.
3. **Report** the run once at the end (`POST /api/v1/external/runs`) so it
   lands on the Operating Record — or open a **live run**
   (start / heartbeat / finish) so the work is visible, and stoppable,
   *while* it happens.

Everything below is plain HTTPS against the dashboard server; the wire
contract is the importable `GET /api/v1/external/openapi.json`. Before you
start, [enroll the agent and mint its `rest` bearer](../external-agents.md)
on the /external-agents page. Token values in this page are placeholders —
never commit a real one.

## Python helper

Copy-paste; the only dependency is `requests`.

```python
# lightwork_client.py — screen-then-act, report-after
import requests


class Lightwork:
    def __init__(self, base_url: str, token: str):
        self.base = base_url.rstrip("/") + "/api/v1/external"
        self.headers = {"Authorization": f"Bearer {token}"}

    def _post(self, path: str, body: dict) -> dict:
        r = requests.post(self.base + path, json=body,
                          headers=self.headers, timeout=15)
        r.raise_for_status()
        return r.json()

    def screen(self, tool: str, detail: str = "", risk: str = "low") -> dict:
        v = self._post("/screen", {"tool": tool, "detail": detail, "risk": risk})
        if not v.get("allowed") and not v.get("requires_approval"):
            raise PermissionError(f"{v.get('rule')}: {v.get('reason')}")
        return v

    def report(self, title: str, outcome: str,
               idempotency_key: str = "", **fields) -> dict:
        return self._post("/runs", {"title": title, "outcome": outcome,
                                    "idempotency_key": idempotency_key, **fields})

    def start(self, title: str, **fields) -> dict:
        return self._post("/runs/start", {"title": title, **fields})

    def heartbeat(self, goal_id: int) -> bool:
        return bool(self._post(f"/runs/{goal_id}/heartbeat", {}).get("continue"))

    def finish(self, goal_id: int, outcome: str, **fields) -> dict:
        return self._post(f"/runs/{goal_id}/finish", {"outcome": outcome, **fields})

    def memory_ingest(self, kind: str, goal_text: str, **fields) -> dict:
        return self._post("/memory/ingest",
                          {"kind": kind, "goal_text": goal_text, **fields})

    def memory_recall(self, query: str, domain: str = "") -> dict:
        return self._post("/memory/recall", {"query": query, "domain": domain})

    def approval(self, approval_id: int, binding_sha256: str) -> dict:
        r = requests.get(f"{self.base}/approvals/{approval_id}",
                         params={"binding_sha256": binding_sha256},
                         headers=self.headers, timeout=15)
        r.raise_for_status()
        return r.json()
```

Semantics worth knowing:

- `screen()` raises `PermissionError` on a **hard deny** — the message
  carries the gateway's `rule` and `reason` (e.g. `capability: tool
  send_contract is denied`). An approval-floor park is *returned*, not
  raised: check `requires_approval` and poll
  `approval(v["approval_id"], v["approval_binding_sha256"])`
  until `status` is `approved` or `denied`. Pass the
  `approval_binding_sha256` returned by `screen()` on every poll; a 409 means
  the reviewed request is stale and must be screened again. An `approved`
  screen result remains advisory. Route the operation through
  `/api/v1/external/execute` when Lightwork must enforce the external write.
- `report()` / `finish()` take an `idempotency_key` — send a stable key per
  logical run and a retried report returns the original record instead of
  double-counting spend.
- `start()` returns `{goal_id, heartbeat_seconds}`; call `heartbeat()` at
  least that often. The recommended interval is shorter than stale-run
  recovery's deadline, leaving room for request delay. `False` is the
  **kill switch** — stop working now.
- `memory_ingest(kind, goal_text, ...)` (`kind` is `success` / `failure` /
  `lesson`) and `memory_recall(query)` reach the governed learning plane
  when `[fleet_memory]` is enabled; an empty `context` with a `reason` is a
  refusal, not an error.

## TypeScript helper

Use the maintained [thin TypeScript client](examples/lightwork.ts) with Node 18+
(or another Fetch runtime with streaming responses). It has a 15-second owned
deadline, a 1-MiB streamed response bound, disposal, safe typed errors and no
automatic retries. No credential or response body is included in an error.

```ts
import { Lightwork, LightworkRequestError } from "./lightwork.js";
const lw = new Lightwork("https://lightwork.example.com", token);
try {
  const verdict = await lw.screen("send_email", JSON.stringify(reviewedEmail), "medium");
  // Do not act here: branch on allowed / requires_approval / denied, and poll
  // the exact approval binding as in the maintained Python example below.
} catch (error) {
  if (error instanceof LightworkRequestError) {
    console.error(error.kind, error.status, error.requestId);
    // authentication/permission: repair access; rate_limit: inspect retryAfterSeconds.
    // unknown_effect: reconcile the original operation; never automatically replay it.
  }
} finally { lw.dispose(); }
```

A timeout or lost response after a POST is `unknown_effect`. An approval 409 is
`stale`; it never authorizes an external effect. `Retry-After` describes a possible
later deliberate attempt, not permission to repeat an uncertain write. Keep the
original report/execution key and reconcile existing receipts first.

## Wiring it into an OpenAI tool-loop

Use the maintained [approval-aware loop](examples/external_agent_loop.py)
alongside `lightwork_client.py` above. It screens the complete copied input,
waits only for its exact approval binding, checks expiry and heartbeat, and
performs zero actions for pending, denied, expired or stale approval. Waiting is
bounded. Exceptions and halt requests finish as `failure` with a separate reason;
only a normal completed loop finishes as `success`. Finalization is called once
with a stable report key. This remains advisory; use governed execution when the
gateway must enforce the write atomically.

```python
from openai import OpenAI
from lightwork_client import Lightwork
from external_agent_loop import run_tool_loop

lw = Lightwork("https://lightwork.example.com", "lw-rest-EXAMPLE")
client = OpenAI()
TOOLS = [{"type": "function", "function": {
    "name": "send_email", "description": "Send a reviewed email.",
    "parameters": {"type": "object", "properties": {
        "to": {"type": "string"}, "body": {"type": "string"}},
        "required": ["to", "body"], "additionalProperties": False}}}]

def complete(messages):
    return client.chat.completions.create(
        model="gpt-4o", messages=messages, tools=TOOLS).choices[0].message

def send_email(to: str, body: str) -> str:
    raise NotImplementedError("Connect your authorized email integration")

receipt = run_tool_loop(lw, complete, send_email, [
    {"role": "user", "content": "Send the Q3 summary to finance."}])
```

The finalizer and external action are never automatically retried after an
uncertain response. Preserve the goal ID and report key for reconciliation.
Local cancellation does not prove a remote side effect stopped.

For a fire-and-forget job that reports only after the fact, skip the
start/heartbeat/finish trio and end with a single
`lw.report(title, "success", steps=[...], cost_dollars=..., idempotency_key=...)`.

## Governed execution (optional)

With `[external_agents] connectors` set (e.g. `["servicenow"]`), your agent
can go beyond asking permission: **Lightwork performs the action itself**
through its SSRF-pinned, egress-allowlisted connector path, with
PREPARE/COMMIT receipts around every effect. Reads (`op: "get"`) run
immediately; a write parks a **digest-bound** approval — once a human
approves, re-send the *identical* request to commit (any change voids it):

```bash
curl -sS -X POST https://lightwork.example.com/api/v1/external/execute \
  -H "Authorization: Bearer lw-rest-EXAMPLEEXAMPLE" \
  -H "Content-Type: application/json" \
  -d '{"connector": "servicenow", "op": "post", "path": "/api/now/table/incident",
       "body": {"short_description": "Renewal follow-up"}}'
# -> {"rule": "approval_required", "approval_id": 57, "execution_id": "kF3...", ...}

curl -sS -X POST https://lightwork.example.com/api/v1/external/executions/kF3.../commit \
  -H "Authorization: Bearer lw-rest-EXAMPLEEXAMPLE" \
  -H "Content-Type: application/json" \
  -d '{"connector": "servicenow", "op": "post", "path": "/api/now/table/incident",
       "body": {"short_description": "Renewal follow-up"}}'
# -> {"rule": "executed", "status": "executed", ...}
```

Full semantics — enabling, connector credentials, `preview`, the 24-hour
TTL, and troubleshooting — in [governed
execution](../external-agents.md#governed-execution).

## Platform-native credentials (optional)

The minted bearer is not the only way in. If the operator pins identity
material on your trust entry, the same endpoints accept [platform-native
credentials](../external-agents.md#platform-native-identity): a
connected-app **JWT** (send it as `Authorization: Bearer <jwt>`; its `sub`
must be your agent id), a webhook-format **HMAC**, or a pinned-key
**Ed25519** request signature. The signed schemes drop the `Authorization`
header and sign the raw body instead:

```python
# HMAC: sha256=hex(HMAC-SHA256(secret, b"<ts>." + raw_body))
import hashlib, hmac, json, time
raw = json.dumps({"tool": "send_email", "risk": "medium"}).encode()
ts = str(int(time.time()))
mac = hmac.new(SECRET.encode(), f"{ts}.".encode() + raw, hashlib.sha256)
headers = {"X-Lightwork-Agent-Id": "sf-quotebot",
           "X-Lightwork-Timestamp": ts,
           "X-Lightwork-Signature": "sha256=" + mac.hexdigest(),
           "Content-Type": "application/json"}
```

The original `X-Maverick-Timestamp` and `X-Maverick-Signature` names still
work. If both names are supplied, each pair must contain identical values.

```python
# Ed25519: sign the domain-separated envelope with your private key
import secrets
nonce = secrets.token_urlsafe(16)                       # single-use
digest = hashlib.sha256(raw).hexdigest()
msg = (f"lightwork-external-request-v1|sf-quotebot|{ts}|{nonce}|"
       f"{digest}".encode())
headers = {"X-Lightwork-Agent-Id": "sf-quotebot",
           "X-Lightwork-Timestamp": ts,
           "X-Lightwork-Nonce": nonce,
           "X-Lightwork-Request-Signature": private_key.sign(msg).hex(),
           "Content-Type": "application/json"}
```

Send the *exact* bytes you signed as the request body (in a Python client,
`maverick.external_identity.envelope_message` builds the Ed25519 message
for you). Timestamps have a 300-second freshness window, so sign at send
time; auth failures stay a generic `401` and the server log names the
reason.

## Operational notes

- **Rate limits** (per agent, per minute): `screen` 120, `runs` 60,
  `approvals` 120, `heartbeat` 240, `memory` 60. A `429` carries
  `Retry-After: 60` — back off and retry.
- **Auth failures are always `401`** — mint a fresh `rest` credential
  (rotation replaces the old token immediately).
- Repeated misbehavior denials auto-contain the agent; an administrator
  releases it on the /external-agents page.

## See also

- [External agents (BYOA)](../external-agents.md) — enrollment, ceilings,
  budget semantics, live runs, and the full troubleshooting table
- `GET /api/v1/external/openapi.json` — the importable machine-readable
  contract for these endpoints
