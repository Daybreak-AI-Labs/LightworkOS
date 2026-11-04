# Lightwork from C# / .NET

Drive a locally running Lightwork swarm from a .NET app over the
[Model Context Protocol](https://modelcontextprotocol.io/). Same
contract every IDE-side MCP client uses — you talk to `maverick mcp`
over stdio JSON-RPC.

This is the official cross-language surface. We don't ship a separate
`Lightwork.Core` NuGet package; we ship one Python kernel and you talk to
it from any language an MCP SDK exists in.

## Prereqs

```bash
# From the root of a source clone (or install Lightwork with the native installer):
python -m pip install -e ./packages/maverick-core -e ./packages/maverick-mcp
dotnet add package ModelContextProtocol           # official C# MCP SDK
```

Target a current LTS (net8.0 or newer). Set your provider key the same
way the CLI expects (e.g. `export ANTHROPIC_API_KEY=…`).

## 20-line quickstart

```csharp
// Program.cs — net8.0+
using ModelContextProtocol.Client;

// Start `maverick mcp` as a subprocess; the SDK manages stdio JSON-RPC.
var transport = new StdioClientTransport(new()
{
    Name = "csharp-quickstart",
    Command = "maverick",
    Arguments = ["mcp"],
});

// CreateAsync performs the MCP initialize handshake.
await using var client = await McpClient.CreateAsync(transport);

var tools = await client.ListToolsAsync();
Console.WriteLine($"Lightwork exposes {tools.Count} tools");

// Start a goal. maverick_start runs the swarm and returns the final
// answer (it's long-running — give it a real budget/timeout).
var result = await client.CallToolAsync("maverick_start", new Dictionary<string, object?>
{
    ["title"] = "Say hello from C#",
    ["description"] = "Reply with a one-line greeting.",
    ["max_dollars"] = 0.25,
});
foreach (var block in result.Content)
{
    Console.WriteLine(block);
}
```

Run with `dotnet run`.

You should see the tool list (10 tools), then the swarm's final answer.

## What works

The MCP server exposes **10 `maverick_*` tools** while the much larger
in-kernel registry stays behind the swarm. The
[registry-backed TypeScript surface table](./typescript-quickstart.md#what-works)
is canonical for names and arguments; it covers goal lifecycle, queued
answers, skills, facts, and governed fleet memory.

## Typed results (`structuredContent`)

Besides the human-readable `result.Content`, every tool returns a
`result.StructuredContent` JSON object matching its `outputSchema`. For example,
`maverick_facts_get` returns `{ "facts": { … } }`, which the SDK exposes as a
`JsonElement`:

```csharp
var factsResult = await client.CallToolAsync("maverick_facts_get");
if (factsResult.StructuredContent is { } structured &&
    structured.TryGetProperty("facts", out var facts))
{
    Console.WriteLine(facts);
}
```

The shapes are identical across languages — see the
[TypeScript quickstart](./typescript-quickstart.md#typed-results-structuredcontent)
for the registry-backed per-tool table.

## Child environment, CLI config, and vaults

This minimal .NET snippet leaves child-environment handling to the SDK, so
`maverick mcp` inherits the .NET process environment. The Python child also
loads the same CLI `config.toml`, dashboard/tenant settings, secret-provider
files, and enabled vaults; credentials are resolved there, not sent as MCP
arguments. For production, apply the
[reviewed filtered-environment policy](./typescript-quickstart.md#child-environment-cli-config-and-vaults)
used by the runnable TypeScript example.

## What's gated

- Third-party tools (Slack, GitHub Actions, S3, Salesforce, …) resolve
  credentials inside the Python child through the CLI's config and secret
  providers; they are not fields in MCP requests.
- Some tools require optional extras (`maverick-agent[redis]`,
  `[s3]`, etc.). Install only what you use.

## Limits — please respect them

- **Multi-agent orchestration stays in Python.** Don't try to
  reimplement the orchestrator-proposer-verifier topology in C#;
  spawn goals and let Lightwork run the swarm. The .NET process is the
  *client*, not a worker.
- **Sandbox / kernel features are Python-side.** Backends
  (firecracker, k8s, devcontainer) live in `maverick-core` and are
  not part of the wire protocol.
- **The MCP server is for cross-language clients, not for tunneling
  Lightwork over the public internet.** Pair with your own auth +
  TLS layer if you go remote (see `http_transport.py` in `packages/maverick-mcp/`).

## Why no `Lightwork.Core` NuGet package?

Thin API clients port well; opinionated frameworks don't. The multi-agent
kernel stays in Python, and every MCP-speaking language, .NET included, can
drive it without giving up features. The decision is recorded under
[Language bindings](./README.md#language-bindings).

## SDK status

The C# MCP SDK is the official
[`ModelContextProtocol`](https://www.nuget.org/packages/ModelContextProtocol)
package (`github.com/modelcontextprotocol/csharp-sdk`). Pin a specific
version and audit the dependency. If the SDK API drifts, the wire
protocol it speaks does not — you can also implement the JSON-RPC
handshake by hand.

## See also

- [Runnable example + CI smoke](../../examples/clients/csharp/) — the executable
  version of this quickstart, run in CI against a live `maverick mcp`.
- [TypeScript client quickstart](./typescript-quickstart.md)
- [Go client quickstart](./go-quickstart.md)
- [Rust client quickstart](./rust-quickstart.md)
- `packages/maverick-mcp/README.md` — what tools are exposed + how
  to wire into Claude Code / Cursor / Continue / Zed
