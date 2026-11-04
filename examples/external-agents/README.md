# External-agent gateway packaging samples

Paste-in platform packaging for the
[bring-your-own-agent gateway](../../docs/external-agents.md): agents built
on other platforms screen every consequential action with Lightwork
*before* acting and report completed runs to the Operating Record. These
samples make the platform side copy-paste instead of build-your-own.

| Sample | What you get |
| --- | --- |
| [`agentforce/`](agentforce/) | Deployable Apex invocable classes (`LightworkGateway.cls` screen action + `LightworkReportRun.cls` run report) over a Named Credential, plus the exact Setup clicks |
| [`bedrock/`](bedrock/) | SAM template + Python 3.12 forwarder Lambda (bearer from Secrets Manager) + the action-group OpenAPI schema `lightwork-external.json`, plus deploy steps |

Both speak the same wire contract — `GET /api/v1/external/openapi.json` on
your Lightwork deployment (`lightwork-external.json` is a verbatim copy).
For hand-rolled runtimes (OpenAI, LangChain, cron jobs), use the
copy-paste Python/TypeScript helpers in the
[external agent quickstart](../../docs/clients/external-agent-quickstart.md)
instead.

## Before either sample: enroll → mint → import

1. **Enable the plane** — `[external_agents] enable = true` and restart the
   dashboard; while off, `/api/v1/external/*` 404s.
2. **Enroll** the agent on the **/external-agents** dashboard page:
   stable `agent_id`, platform (`agentforce` / `bedrock`), tool + risk +
   budget ceilings, expiry. The agent becomes principal `agent:<id>` on
   the Operating Record.
3. **Mint** the `rest` credential from the agent's detail page. The
   `lw-rest-…` token is shown **exactly once** — put it straight into the
   platform's secret store (Salesforce External Credential header /
   AWS Secrets Manager). Rotation = mint again; the old token 401s
   immediately.
4. **Import** the packaging: follow [`agentforce/README.md`](agentforce/README.md)
   or [`bedrock/README.md`](bedrock/README.md).

Every token in these samples is an obviously fake placeholder
(`lw-rest-EXAMPLE`); never commit a real one.
