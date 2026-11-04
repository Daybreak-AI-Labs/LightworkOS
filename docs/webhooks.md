# Outbound webhooks

Lightwork can tell another system when something happens to a goal, a
data-subject request, a privacy incident, an assessment, a vendor contract,
an approval or a policy. Each event is one signed HTTP POST to every
subscription whose filter matches. Deliveries are logged and retried; a
delivery that keeps failing is parked as *dead* until someone retries it.

## Subscriptions

Manage subscriptions on **Settings → Secure connected automations → Manage
webhook subscriptions and deliveries** (`/settings/webhooks/manage`), or over
the API:

| Method | Path | What it does |
|---|---|---|
| `GET` | `/api/v1/webhooks/subscriptions` | List subscriptions (secrets are never returned) plus the legacy address list. |
| `POST` | `/api/v1/webhooks/subscriptions` | Create: `{url, events, secret, description, enabled}`. |
| `GET` / `PATCH` | `/api/v1/webhooks/subscriptions/{id}` | Read or change one (any subset of the fields above; an empty `secret` clears it). |
| `POST` | `/api/v1/webhooks/subscriptions/{id}/test` | Send a `webhook.test` event now. |
| `GET` | `/api/v1/webhooks/deliveries?subscription_id=&status=&limit=` | The delivery log. |
| `GET` | `/api/v1/webhooks/deliveries/{id}` | One delivery with its full body and attempt log. |
| `POST` | `/api/v1/webhooks/deliveries/{id}/retry` | Retry now (also revives a dead delivery). |
| `GET` | `/api/v1/webhooks/events` | The event catalogue. |

All of these need the workspace `admin` role (the same as the signing-secret
panel); every change is written to the activity log before it happens.

`events` is `"*"` (everything), a family such as `"dsar.*"`, or exact names.
The address must be `https://` on a public host: it is checked with the same
guard the dispatcher uses, so a subscription can never point at a loopback,
link-local or private address, and the connection is pinned to the address
that was checked.

### The legacy address list

```toml
[webhooks]
outbound = ["https://example.com/maverick-hook"]
secret = "${MAVERICK_WEBHOOK_SECRET}"
```

still works as a *default subscription*: every event goes to every address
in the list, signed with `[webhooks] secret`, and those deliveries appear in
the log under the subscription id `legacy-config`. Set
`[webhooks] subscriptions = false` (or `MAVERICK_WEBHOOK_SUBSCRIPTIONS=0`)
to go back to one-shot delivery with no log.

## Envelope

Every POST body is this JSON object:

```json
{
  "v": 1,
  "id": "evt_5f1c…",
  "event": "dsar.opened",
  "type": "dsar.opened",
  "ts": 1790000000.12,
  "occurred_at": 1790000000.12,
  "workspace": "acme",
  "record": {"type": "dsar", "id": "DSAR-42", "title": "access request from a@b.com", "status": "open", "due_at": 1792592000.0},
  "link": "https://lightwork.example.com/privacy/dsar/DSAR-42",
  "payload": {}
}
```

| Field | Meaning |
|---|---|
| `v` | Envelope version, always `1`. |
| `id` | Unique event id (`evt_` + 32 hex). Also sent as the `X-Lightwork-Delivery` header and matching legacy alias. Retries carry the same id, so receivers can de-duplicate. |
| `event`, `type` | The event name (the two fields are the same; `event` is the original name, `type` the documented one). |
| `ts`, `occurred_at` | When it happened, seconds since the epoch (the same value). |
| `workspace` | The workspace (tenant) id, or `""` for a single-workspace installation. |
| `record` | `null` for goal events. Otherwise `type`, `id`, `title` and a short summary (status, deadline, assignee…) of the record the event is about. |
| `link` | Where to open the record. Absolute when `[dashboard] public_url` (or `MAVERICK_PUBLIC_URL`) is set, otherwise a path. |
| `payload` | Event-specific details (the pre-existing goal payloads are unchanged). |

## Events

| Event | Record | When |
|---|---|---|
| `goal_created`, `goal_finished`, `episode_finished`, `final_emitted` | goal | Run lifecycle (unchanged). |
| `deliverable.approved` | deliverable | A gated deliverable was signed off (sent only to `[deliverables] handoff_webhook`). |
| `dsar.opened` | dsar | A data-subject request was opened. |
| `dsar.verified` | dsar | The requester's identity was verified. |
| `dsar.acknowledged` | dsar | Receipt was confirmed to the requester (the CCPA's 10-business-day step). |
| `dsar.due_soon` | dsar | The request is inside a warning window or due today (`payload.state` says which). |
| `dsar.overdue` | dsar | The request passed its deadline. |
| `dsar.extended` | dsar | The deadline was extended. |
| `dsar.closed` | dsar | The request was answered or closed. |
| `incident.opened` | incident | An incident was opened; the 72-hour clock started. |
| `incident.notifiable_decided` | incident | Someone recorded whether it must be notified. |
| `incident.due_soon` | incident | The 72-hour deadline is close or has passed (`payload.state`). |
| `incident.closed` | incident | The incident was closed. |
| `assessment.assigned` | assessment | Put on (or taken off) someone's desk. |
| `assessment.decided` | assessment | Approved or rejected. |
| `assessment.renewal_due` | assessment | A renewal or review date is close or has passed. |
| `vendor.contract_renewal_due` | vendor | A contract renewal is close or has passed. |
| `vendor.review_due` | vendor | A vendor review is due. |
| `approval.created` | approval | An action was parked for human approval. |
| `approval.decided` | approval | Approved or denied (single approver, or the quorum's final decision). |
| `approval.undone` | approval | A decision on a request a waiting task holds was undone within its undo window (`[approval] undo_grace_seconds`); the approval is waiting again. Payload: `previous_status`, `undone_by`. Other decisions are final and never undone. |
| `approval.expired` | approval | An approval card expired before anyone decided. |
| `policy.published` | policy | A policy version was published. |
| `webhook.test` | webhook_subscription | Sent from the Webhooks page. |

`dsar.verified`, `dsar.acknowledged` and `dsar.extended` are sent when the
matching change is recorded on the request (from the dashboard tracker or the
public rights form). `vendor.review_due` is in the catalogue so subscriptions
can be created for it now; it is emitted once vendors carry review dates.

## Signed messages and compatible header names

When a subscription (or the legacy list) has a secret, each request carries:

```
X-Lightwork-Timestamp: 1790000000
X-Lightwork-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>." + body)>
X-Lightwork-Event: dsar.opened
X-Lightwork-Delivery: evt_5f1c…
```

The matching `X-Maverick-*` headers are also sent for existing integrations.
Both names carry the same values, signed bytes and signing key. Lightwork's
inbound receivers accept either name or matching pairs. Conflicting signature
or timestamp headers are rejected; they are never resolved by choosing one.

Verify with `maverick.webhooks.verify_signature(body, signature, secret,
timestamp=timestamp)`, or in any language: HMAC-SHA256 the bytes
`timestamp + "." + raw body` with the secret, hex-encode, prefix `sha256=`,
compare in constant time, and reject timestamps older than your replay window
(Lightwork's own receivers use 300 seconds). A retry is a fresh request with a
fresh timestamp and signature over the same body.

## Retries and the dead-letter state

| Attempt | When |
|---|---|
| 1 | Immediately. |
| 2 | About 1 minute later. |
| 3 | About 5 minutes after that. |
| 4 | About 15 minutes after that. |
| 5 | About 40 minutes after that. |

Each wait is jittered by ±20 %. Only HTTP 200–299 confirms that the receiving
system accepted the request; it does not prove that its later actions finished.
After the fifth known unsuccessful reply the delivery is **dead**: it stays in
the log with every attempt's status code, latency and the first 200 characters
of the response. "Retry now" is available for known unsuccessful deliveries.
An active or unconfirmed send is never automatically repeated. Read its
original record; the separate reviewed new-attempt control warns that another
send may duplicate an action in the receiving system. Retries are
run by the dashboard's background scheduler
(`maverick_dashboard.deadline_alerts_scheduler`), which also evaluates
deadline alerts; without the dashboard running, only the first attempt is
made. A host outside the enterprise egress allow-list is dead immediately and
never retried.

## Inbound webhooks

This page covers outbound deliveries. Inbound control requests use a separate
`MAVERICK_INBOUND_WEBHOOK_SECRET`. Configure each Linear, Jira, GitLab and
GitHub integration and actionable flow approval links with a distinct
credential as described in `env-vars.md`. Callers and providers must use those
credentials before they rely on the inbound routes, and approval links issued
before an approval key is set must be reissued after it is set.
