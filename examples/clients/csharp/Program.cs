// Runnable C# / .NET MCP client for Lightwork.
//
// The executable version of docs/clients/csharp-quickstart.md and the CI smoke
// for the .NET cross-language surface. It spawns `maverick mcp` (stdio JSON-RPC)
// and runs the documented client flow:
//
//   initialize  ->  tools/list  ->  a no-LLM tools/call (maverick_facts_get)
//
// It deliberately does NOT call maverick_start: that runs the swarm and needs a
// provider key + budget, so it isn't suitable for an unattended CI check.
//
// Run locally:  dotnet run
using ModelContextProtocol.Client;
using System.Text.Json;

// Start `maverick mcp` as a subprocess; the SDK manages stdio JSON-RPC.
var transport = new StdioClientTransport(new()
{
    Name = "maverick-csharp-example",
    Command = "maverick",
    Arguments = ["mcp"],
});

// CreateAsync performs the MCP initialize handshake.
await using var client = await McpClient.CreateAsync(transport);

var tools = await client.ListToolsAsync();
var names = tools.Select(t => t.Name).OrderBy(n => n).ToArray();
Console.WriteLine($"Lightwork exposes {tools.Count} tools: {string.Join(", ", names)}");
foreach (var expected in new[] { "maverick_start", "maverick_status", "maverick_facts_get" })
{
    if (!names.Contains(expected))
    {
        Console.Error.WriteLine($"MCP server is missing tool '{expected}'");
        return 1;
    }
}

// A no-LLM round-trip: maverick_facts_get just reads the persistent world model.
var res = await client.CallToolAsync("maverick_facts_get");
if (res.Content.Count == 0)
{
    Console.Error.WriteLine("maverick_facts_get returned no content");
    return 1;
}
Console.WriteLine("maverick_facts_get round-trip OK");

if (res.StructuredContent is not { } structured ||
    structured.ValueKind != JsonValueKind.Object ||
    !structured.TryGetProperty("facts", out _))
{
    Console.Error.WriteLine(
        "maverick_facts_get returned no structuredContent with 'facts'");
    return 1;
}
Console.WriteLine("maverick_facts_get structuredContent OK");

Console.WriteLine("OK: C# client drove Lightwork over MCP end-to-end");
return 0;
