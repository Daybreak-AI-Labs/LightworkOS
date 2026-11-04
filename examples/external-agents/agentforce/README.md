# Agentforce → Lightwork gateway (paste-in Apex)

Bring a Salesforce Agentforce agent under Lightwork governance with two
deployable invocable actions — no External Services registration required:

| File | Invocable action | Gateway call |
| --- | --- | --- |
| `LightworkGateway.cls` | **Lightwork: Screen Action** (tool, detail, risk → allowed, rule, reason, requiresApproval, approvalId) | `POST /api/v1/external/screen` |
| `LightworkReportRun.cls` | **Lightwork: Report Run** (title, outcome, costDollars, idempotencyKey → ok, goalId, overBudget, errorMessage) | `POST /api/v1/external/runs` |

Two classes because Apex permits exactly one `@InvocableMethod` per class;
`LightworkReportRun` reuses `LightworkGateway`'s shared HTTP/JSON plumbing.
Both call out through the Named Credential `Lightwork_Gateway`, so the
per-agent `rest` bearer lives in Salesforce credential storage — never in
Apex, debug logs, or version control. Callout timeout is 30 s; any non-2xx
or callout exception comes back as a readable message in the action result
(the screen action stays **fail-closed**: a transport error is
`allowed = false`, never an implicit allow).

Before you start, on the Lightwork side ([docs](../../../docs/external-agents.md)):
enable `[external_agents]`, enroll the agent on **/external-agents**
(platform `agentforce`), and mint its `rest` credential — the
`lw-rest-…` token is shown exactly once. Every token below is a fake
placeholder (`lw-rest-EXAMPLE`).

## Setup clicks

### 1. External Credential (holds the bearer)

1. **Setup → Security → Named Credentials → External Credentials** tab →
   **New**.
2. Label: `Lightwork Gateway Auth` · Name: `Lightwork_Gateway_Auth` ·
   Authentication Protocol: **Custom**. Save.
3. On the External Credential detail, under **Principals** → **New**:
   Parameter Name: `Agent`, Sequence Number: `1`. Save.
4. Under **Custom Headers** → **New**:
   - Name: `Authorization`
   - Value: `Bearer lw-rest-EXAMPLE` ← paste your real minted token here
   - Sequence Number: `1`. Save.
5. Grant access: **Setup → Users → Permission Sets** → **New**
   (e.g. `Lightwork Gateway Access`) → on the permission set, open
   **External Credential Principal Access** → **Edit** → add
   `Lightwork_Gateway_Auth - Agent` → Save. Assign the permission set to
   the user(s) the agent runs as (for Agentforce, include the Agent User).

### 2. Named Credential (holds the URL)

1. **Setup → Security → Named Credentials → Named Credentials** tab →
   **New**.
2. Label: `Lightwork Gateway` · Name: `Lightwork_Gateway` — the API name
   **must** be exactly `Lightwork_Gateway`; the Apex endpoint is
   `callout:Lightwork_Gateway/api/v1/external/...`.
3. URL: your Lightwork base URL, e.g. `https://lightwork.example.com`
   (no trailing slash, no path — Apex appends `/api/v1/external/...`).
4. External Credential: `Lightwork Gateway Auth`.
5. Leave **Generate Authorization Header** unchecked — the External
   Credential's custom header supplies `Authorization`. Save.

### 3. Deploy the classes

With Salesforce CLI, from this directory (the `-meta.xml` files are
included):

```bash
sf project deploy start --source-dir . --target-org your-org-alias
```

Or paste each class into **Developer Console → File → New → Apex Class**
(`LightworkGateway` first — `LightworkReportRun` references it).

### 4. Add the actions to the agent topic

1. **Setup → Agentforce Agents** (Agent Builder) → open your agent →
   open (or create) the topic that performs consequential work.
2. **This Topic's Actions → New → Add from Asset Library / Apex** →
   add **Lightwork: Screen Action** and **Lightwork: Report Run**
   (they appear under the invocable-action labels above).
3. In the topic **Instructions**, add:

   > Before ANY consequential action (sending, posting, changing records
   > outside this org, spending money), run *Lightwork: Screen Action*
   > with the tool name, a one-line detail, and your risk estimate
   > (low/medium/high). Proceed only when `allowed` is true. If
   > `requiresApproval` is true, tell the user a human approval is
   > pending (id `approvalId`) and do not act until it is granted.
   > Otherwise `reason` explains the refusal — re-plan instead of
   > retrying. When the job completes, run *Lightwork: Report Run* exactly
   > once with a short title, `success` or `failure`, the total cost in
   > dollars, and a stable idempotency key.

## Verifying

Run one screen from **Developer Console → Debug → Open Execute Anonymous
Window** (user must hold the permission set):

```apex
LightworkGateway.ScreenRequest r = new LightworkGateway.ScreenRequest();
r.tool = 'send_email';
r.detail = 'smoke test from Agentforce setup';
r.risk = 'low';
System.debug(LightworkGateway.screen(new List<LightworkGateway.ScreenRequest>{ r })[0]);
```

Expect `allowed=true, rule=allow` (and an `external_action_screened` audit
event on the Lightwork side). A readable `transport_error` reason tells you
which side to fix — 401 token, 403 license, 404 plane off, 429 rate limit.

## Notes

- **Rotation**: mint a new `rest` credential on /external-agents, then
  update the External Credential's `Authorization` custom header value.
  The old token 401s immediately.
- **Approval polling**: a parked approval is decided by a human in the
  Lightwork dashboard queue; the row id is `approvalId`. To poll from
  Salesforce, add a third class with a GET callout to
  `/api/v1/external/approvals/{id}` following the same pattern, or let
  the agent re-attempt later. The full endpoint contract is
  `GET /api/v1/external/openapi.json`.
- Prefer schema import over Apex? The gateway's OpenAPI drops directly
  into **Setup → External Services** (see the
  [platform docs](../../../docs/external-agents.md)); this sample is the
  more controllable path — explicit fail-closed handling, readable errors,
  no External Services registration.
