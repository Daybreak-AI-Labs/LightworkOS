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

## Untrusted server output

The example refuses tool errors and malformed `facts` results, bounds paginated
tool metadata, and escapes terminal controls in displayed server text.
`BoundedStdioServer` owns the child process and supplies the SDK's public
`StreamClientTransport` with byte-limited streams: 16 MiB per stdout message and
64 KiB per stderr line. After the read-only exchange, cleanup closes stdin and
gives the server one second to run its own shutdown; a non-zero exit is
reported as a failure. Only a server that does not exit has its process tree
killed. On Linux, descendants recorded before stdin closes are also terminated
after the server exits, so a re-parented child cannot outlive cleanup.
It does not contain descendants that independently detach before cleanup.
Initialization and the read-only smoke requests share a 30-second deadline.

After building, set `MCP_BOUNDARY_COMMAND` to a JSON argument array invoking the
built executable and run `python3 -m pytest` on the `StdioBoundaries`,
`PipedStreamBounds` and `ResponseDeadline` classes in
`examples/clients/java/tests/test_stdio_boundaries.py` from the repository root.
The shared fixture launches a disposable stdio server without model calls.
Without `MCP_BOUNDARY_COMMAND`, generic Python test runs skip this native fixture.
The client workflow runs the live smoke; these adversarial checks are run
separately with a built client.
