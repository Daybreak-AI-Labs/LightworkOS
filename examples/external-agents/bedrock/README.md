# Bedrock agent → Lightwork gateway (paste-in SAM)

Bring an Amazon Bedrock agent under Lightwork governance with one action
group and one small forwarder Lambda:

| File | Role |
| --- | --- |
| `template.yaml` | SAM template: the forwarder Lambda, its Secrets Manager read policy, and the Bedrock invoke permission |
| `forwarder/app.py` | Python 3.12 Lambda: Bedrock action-group event → Lightwork gateway call → action-group response (stdlib + boto3 only) |
| `lightwork-external.json` | The action-group OpenAPI schema — a verbatim copy of the gateway's own contract (`GET /api/v1/external/openapi.json`) |

The Lambda maps each operation (`screenAction`, `reportRun`, `startRun`,
`heartbeatRun`, `finishRun`, `memoryIngest`, `memoryRecall`,
`approvalStatus`, `executeAction`, `executionStatus`, `commitExecution`)
onto the matching `/api/v1/external/...` route, attaches
the per-agent `rest` bearer read from AWS Secrets Manager (never
hard-coded), and returns the gateway's status + JSON body in the Bedrock
action-group response shape — so a governance deny reaches the model as a
readable verdict it can re-plan around, not a Lambda crash. On a `401` it
re-reads the secret once and retries, making token rotation seamless.

Before you start, on the Lightwork side ([docs](../../../docs/external-agents.md)):
enable `[external_agents]`, enroll the agent on **/external-agents**
(platform `bedrock`), and mint its `rest` credential — the `lw-rest-…`
token is shown exactly once. Every token below is a fake placeholder
(`lw-rest-EXAMPLE`).

## Deploy

### 1. Create the secret

```bash
aws secretsmanager create-secret \
  --name lightwork/gateway-token \
  --secret-string 'lw-rest-EXAMPLE'   # paste the real minted token
```

Note the returned `ARN`.

### 2. Deploy the forwarder

From this directory (SAM CLI ≥ 1.100):

```bash
sam build
sam deploy --guided \
  --parameter-overrides \
    LightworkBaseUrl=https://lightwork.example.com \
    TokenSecretArn=arn:aws:secretsmanager:us-east-1:111122223333:secret:lightwork/gateway-token-AbCdEf
```

Accept the guided defaults (stack name e.g. `lightwork-gateway-forwarder`).
The stack output `ForwarderFunctionArn` is the action-group executor.

### 3. Wire the action group

In the Bedrock console (**Amazon Bedrock → Agents → your agent →
Edit → Action groups → Add**):

1. Name: `lightwork-gateway`.
2. Action group type: **Define with API schemas**.
3. Action group invocation: **Select an existing Lambda function** → pick
   the deployed forwarder (`ForwarderFunctionArn`). The template already
   grants `bedrock.amazonaws.com` invoke permission for this account.
4. Action group schema: **Define via in-line schema editor** → paste the
   contents of `lightwork-external.json` — or upload it to S3 first and
   select it there. (You can also fetch it live:
   `curl -H "Authorization: Bearer lw-rest-EXAMPLE" https://lightwork.example.com/api/v1/external/openapi.json`.)
   The packaged schema and forwarder cover the same gateway operations,
   including runtime evaluation. Red-team operations are optional: the live
   schema omits them when that feature is disabled. Prefer the live schema
   from the same Lightwork release as the forwarder; importing those optional
   operations does not enable the server feature. The contract regression
   checks packaged operation, parameter and request-property parity with the
   gateway schema.
5. Save, then **Prepare** the agent.

### 4. Instruct the agent

Add to the agent instructions:

> Before ANY consequential action (sending, posting, changing external
> systems, spending money), call `screenAction` with the tool name, a
> one-line detail, and your risk estimate (low/medium/high). Proceed only
> when `allowed` is true. If `requires_approval` is true, poll
> `approvalStatus` with the returned `approval_id` until a human decides.
> When the job completes, call `reportRun` exactly once with a short
> title, `success` or `failure`, the total cost in dollars, and a stable
> `idempotency_key`. For long jobs, use `startRun` /
> `heartbeatRun` / `finishRun` instead — stop immediately if a heartbeat
> returns `continue: false`.

### 5. Verify

Test the agent with a benign prompt that triggers a screened tool; expect
an `allowed: true` verdict in the trace and an `external_action_screened`
audit event on the Lightwork side. Direct Lambda smoke test:

```bash
aws lambda invoke --function-name <ForwarderFunctionArn> --payload '{
  "messageVersion": "1.0", "actionGroup": "lightwork-gateway",
  "apiPath": "/api/v1/external/screen", "httpMethod": "POST",
  "requestBody": {"content": {"application/json": {"properties": [
    {"name": "tool", "type": "string", "value": "send_email"},
    {"name": "detail", "type": "string", "value": "smoke test"},
    {"name": "risk", "type": "string", "value": "low"}]}}}
}' --cli-binary-format raw-in-base64-out /dev/stdout
```

## Rotation and troubleshooting

- **Rotation**: mint a new `rest` credential on /external-agents, then
  `aws secretsmanager put-secret-value --secret-id lightwork/gateway-token
  --secret-string 'lw-rest-EXAMPLE'`. The forwarder's cache refreshes
  within ~5 minutes and immediately on the first `401`.
- A `404` from the gateway means the external-agents plane is off; `403`
  means a governance refusal; `429` is the per-agent rate limit (honor
  `Retry-After`). The full rule table is in the
  [platform docs](../../../docs/external-agents.md).
- Prefer *return of control*? Skip the Lambda and let your orchestrating
  app forward operations itself — the schema and route table stay
  identical.
