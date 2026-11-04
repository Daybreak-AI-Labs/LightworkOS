/**
 * Runnable TypeScript MCP client for Lightwork.
 *
 * This is the executable version of docs/clients/typescript-quickstart.md and
 * the CI smoke test for the cross-language surface. It spawns `maverick mcp`
 * (stdio JSON-RPC) and exercises the documented client flow:
 *
 *   initialize  ->  tools/list  ->  a no-LLM tools/call (maverick_facts_get)
 *
 * It deliberately does NOT call maverick_start: that runs the swarm and needs a
 * provider key + budget, so it isn't suitable for an unattended CI check.
 *
 * Run locally:  npm install && npm run check
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { strict as assert } from "node:assert";

import { selectLightworkMcpEnvironment } from "./environment.js";

// Do not hand the MCP child the ambient process environment. The pure helper
// forwards Lightwork's namespace plus an exact provider/runtime allowlist.
const serverEnv = selectLightworkMcpEnvironment(process.env);
const transport = new StdioClientTransport({
  command: "maverick",
  args: ["mcp"],
  env: serverEnv,
});
const client = new Client(
  { name: "maverick-ts-example", version: "0.1.0" },
  { capabilities: {} },
);

// connect() performs the MCP initialize handshake.
await client.connect(transport);

// try/finally so a failed assertion still closes the client and reaps the
// spawned `maverick mcp` child process instead of leaking it.
try {
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name).sort();
  console.log(`Lightwork exposes ${tools.length} tools: ${names.join(", ")}`);
  for (const expected of ["maverick_start", "maverick_status", "maverick_facts_get"]) {
    assert.ok(names.includes(expected), `MCP server is missing tool '${expected}'`);
  }

  // A no-LLM round-trip: maverick_facts_get just reads the persistent world model.
  const res = await client.callTool({ name: "maverick_facts_get", arguments: {} });
  assert.ok(res.content, "maverick_facts_get returned no content");
  console.log("maverick_facts_get round-trip OK");

  // Every Lightwork tool also returns structuredContent: typed JSON matching the
  // tool's outputSchema, so a typed client reads parsed fields instead of
  // re-parsing the human-readable text block. facts_get -> { facts: {...} }.
  const structured = res.structuredContent;
  assert.ok(structured, "maverick_facts_get returned no structuredContent");
  assert.ok(
    typeof structured === "object" &&
      structured !== null &&
      "facts" in structured,
    "structuredContent is missing the 'facts' key",
  );
  console.log(
    "maverick_facts_get structuredContent OK:",
    JSON.stringify(structured),
  );
} finally {
  await client.close();
}
console.log("OK: TypeScript client drove Lightwork over MCP end-to-end");
