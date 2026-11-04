# TypeScript MCP client example

The runnable version of [`docs/clients/typescript-quickstart.md`](../../../docs/clients/typescript-quickstart.md),
and the CI smoke test for Lightwork's cross-language MCP surface.

`client.ts` spawns `maverick mcp` (stdio JSON-RPC) and runs the documented
client flow — `initialize` → `tools/list` → a no-LLM `tools/call`
(`maverick_facts_get`). It does **not** call `maverick_start` (that runs the
swarm and needs a provider key + budget), so it's safe to run unattended.

## Run it

```bash
# PyPI publish is pending — until the first tagged release, install the `maverick`
# CLI from a source clone (`pip install -e packages/maverick-core packages/maverick-mcp`)
# or via the native installer (see Releases).
python -m pip install -e ./packages/maverick-core -e ./packages/maverick-mcp
npm install
npm run check
```

Expected output ends with:

```
Lightwork exposes 10 tools: maverick_answer, maverick_fact_set, ...
maverick_facts_get round-trip OK
maverick_facts_get structuredContent OK: {"facts":{...}}
OK: TypeScript client drove Lightwork over MCP end-to-end
```

CI runs exactly this on every change to the MCP server or the clients (see
`.github/workflows/mcp-clients.yml`), so a break in `maverick mcp` or the
documented tool surface fails the build.

This example passes a reviewed child environment rather than all of
`process.env`: Lightwork-owned settings, provider/identity inputs, and required
runtime/proxy/CA names only. The Python child still loads the normal CLI config
and enabled vaults. See the
[client quickstart](../../../docs/clients/typescript-quickstart.md#child-environment-cli-config-and-vaults)
for the exact boundary.
