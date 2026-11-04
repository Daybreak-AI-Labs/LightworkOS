# C# / .NET MCP client example

The runnable version of [`docs/clients/csharp-quickstart.md`](../../../docs/clients/csharp-quickstart.md),
and the CI smoke test for Lightwork's cross-language MCP surface.

`Program.cs` spawns `maverick mcp` (stdio JSON-RPC) and runs the documented
client flow — `initialize` → `tools/list` → a no-LLM `tools/call`
(`maverick_facts_get`). It does **not** call `maverick_start` (that runs the
swarm and needs a provider key + budget), so it's safe to run unattended.

## Run it

```bash
# PyPI publish is pending — until the first tagged release, install the `maverick`
# CLI from a source clone (`pip install -e packages/maverick-core packages/maverick-mcp`)
# or via the native installer (see Releases).
python -m pip install -e ./packages/maverick-core -e ./packages/maverick-mcp
dotnet run
```

Expected output ends with:

```
Lightwork exposes 10 tools: maverick_answer, maverick_fact_set, ...
maverick_facts_get round-trip OK
maverick_facts_get structuredContent OK
OK: C# client drove Lightwork over MCP end-to-end
```

CI runs exactly this on every change to the MCP server or the clients (see
`.github/workflows/mcp-client-csharp.yml`), so a break in `maverick mcp` or the
documented tool surface fails the build.

The minimal .NET launcher inherits the parent process environment;
`maverick mcp` also loads the usual CLI config and enabled vaults. For a
production launcher, use the reviewed boundary described in the
[TypeScript client quickstart](../../../docs/clients/typescript-quickstart.md#child-environment-cli-config-and-vaults).

The official C# MCP SDK is the [`ModelContextProtocol`](https://www.nuget.org/packages/ModelContextProtocol)
NuGet package, pinned in `Lightwork.McpClient.Example.csproj` for reproducible CI.
