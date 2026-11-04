# Lightwork from TypeScript / JavaScript

Drive a locally running Lightwork swarm from a TS / Node app over the
[Model Context Protocol](https://modelcontextprotocol.io/). Same
contract every IDE-side MCP client uses — you talk to `maverick mcp`
over stdio JSON-RPC.

This is the official cross-language surface. We don't ship a separate
`@maverick/core` port; we ship one Python kernel and you talk to it
from any language an MCP SDK exists in.

## Prereqs

```bash
# From the root of a source clone (or install Lightwork with the native installer):
python -m pip install -e ./packages/maverick-core -e ./packages/maverick-mcp
npm i @modelcontextprotocol/sdk
```

Set your provider key the same way the CLI expects (e.g.
`export ANTHROPIC_API_KEY=…`).

Copy the runnable example's
[`environment.ts`](../../examples/clients/typescript/environment.ts) beside
`quickstart.ts`. That helper is the single reviewed child-environment
allowlist; the contract test keeps it aligned with every configured provider.

## Quickstart

```ts
// quickstart.ts — node 20+ / bun / deno
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { selectLightworkMcpEnvironment } from "./environment.js";

const serverEnv = selectLightworkMcpEnvironment(process.env);
const transport = new StdioClientTransport({
  command: "maverick",
  args: ["mcp"],
  // Do not pass process.env: unrelated secrets and Python injection knobs stay out.
  env: serverEnv,
});

const client = new Client({ name: "ts-quickstart", version: "0.1.0" }, {
  capabilities: {},
});
await client.connect(transport);

const tools = await client.listTools();
console.log("Lightwork exposes", tools.tools.length, "tools");

// Start a goal. maverick_start runs the swarm and returns the final
// answer (it's long-running — give it a real budget/timeout).
const result = await client.callTool({
  name: "maverick_start",
  arguments: {
    title: "Say hello from TypeScript",
    description: "Reply with a one-line greeting.",
    max_dollars: 0.25,
  },
});
console.log(result.content);

await client.close();
```

Run with `npx tsx quickstart.ts` (or `bun run quickstart.ts`,
`deno run --allow-all quickstart.ts`).

You should see the tool list (10 tools), then the swarm's final answer.

## What works

The MCP server exposes a small, stable control surface — **10
`maverick_*` tools** — while the much larger in-kernel registry stays behind
the swarm. You drive the swarm; the kernel runs those internal tools.

- `maverick_start` `{title, description?, max_dollars?, max_wall_seconds?, max_depth?}`
  — start a goal; returns the final answer.
- `maverick_status` — list recent goals + open questions.
- `maverick_resume` `{goal_id}` — resume a paused goal.
- `maverick_answer` `{question_id, answer}` — answer a queued question.
- `maverick_skill_install` `{source}` / `maverick_skills_list`.
- `maverick_fact_set` `{key, value}` / `maverick_facts_get`.
- `maverick_fleet_ingest`
  `{agent_id, vendor, kind, goal_text, reflection?, domain?}` — deposit an
  external agent's experience into governed fleet memory (roster-gated).
- `maverick_fleet_recall` `{agent_id, vendor, query, domain?}` — governed, audited
  memory read for an external fleet agent.

In-kernel tools such as web search, repo map, editor, Slack, and S3 are **not**
individually exposed over MCP — the swarm decides which to use while running a
goal.

## Typed results (`structuredContent`)

Every tool returns two things: the human-readable `content` text block
(unchanged, for back-compat) and a `structuredContent` object — typed
JSON matching the tool's `outputSchema`. Typed clients read the latter
and skip re-parsing prose:

```ts
const res = await client.callTool({ name: "maverick_facts_get", arguments: {} });
console.log(res.structuredContent);   // { facts: { … } }
```

The shape per tool:

| tool | `structuredContent` |
|------|---------------------|
| `maverick_start`, `maverick_resume` | `{ goal_id, answer }` |
| `maverick_status` | `{ goals, open_questions }` |
| `maverick_answer` | `{ question_id }` |
| `maverick_skill_install` | `{ name, path }` |
| `maverick_skills_list` | `{ skills }` |
| `maverick_fact_set` | `{ key }` |
| `maverick_fleet_ingest` | `{ ok, reason }` |
| `maverick_fleet_recall` | `{ context?, reason }` |
| `maverick_facts_get` | `{ facts }` |

`maverick_start` / `maverick_resume` expose `goal_id` so you can chain a
follow-up `maverick_status` or `maverick_resume` without scraping it out
of the text block.

## Child environment, CLI config, and vaults

The runnable TypeScript example deliberately gives the MCP child a **filtered**
environment, not all of `process.env`. It forwards Lightwork-owned
`MAVERICK_*` settings and their supported `LIGHTWORK_*` aliases, plus the
reviewed provider, identity, proxy/CA, and runtime names in
`LIGHTWORK_MCP_ENV_ALLOWLIST`. Unrelated ambient secrets and Python injection
variables stay out.

Filtering the environment does not create a second configuration system. The
child still runs the same CLI entry point and, through the forwarded
home/config path variables, loads the same `config.toml`, dashboard overlay,
tenant selection, mounted secret-provider files, and enabled OAuth/browser
vaults. Provider keys may therefore come from an explicitly forwarded provider
variable or the normal Lightwork config/secret path. The Java, C#, Go, and Rust
minimal snippets rely on their SDKs' inherited child environment; production
launchers should apply an equivalent reviewed allowlist.

## What's gated

- Third-party tools (Slack, GitHub Actions, S3, Salesforce, …) resolve
  credentials inside the Python child through the same CLI config and secret
  providers; they are not fields in MCP requests.
- Some tools require optional extras (`maverick-agent[redis]`,
  `[s3]`, etc.). Install only what you use.

## Limits — please respect them

- **Multi-agent orchestration stays in Python.** Don't try to
  reimplement the orchestrator-proposer-verifier topology in TS;
  spawn goals and let Lightwork run the swarm. The TS process is the
  *client*, not a worker.
- **Sandbox / kernel features are Python-side.** Backends
  (firecracker, k8s, devcontainer) live in `maverick-core` and are
  not part of the wire protocol.
- **The MCP server is for cross-language clients, not for tunneling
  Lightwork over the public internet.** Pair with your own auth +
  TLS layer if you go remote (see `http_transport.py` in `packages/maverick-mcp/`).

## Why no `npm install @maverick/core`?

Thin API clients port well; opinionated frameworks don't. The multi-agent
kernel stays in Python, and every MCP-speaking language can drive it without
giving up features. The decision, and when a thin TypeScript client package
would be considered, are recorded under
[Language bindings](./README.md#language-bindings).

## See also

- [Go client quickstart](./go-quickstart.md)
- [Rust client quickstart](./rust-quickstart.md)
- [C# / .NET client quickstart](./csharp-quickstart.md)
- [Java / JVM client quickstart](./java-quickstart.md)
- `packages/maverick-mcp/README.md` — what tools are exposed + how
  to wire into Claude Code / Cursor / Continue / Zed
