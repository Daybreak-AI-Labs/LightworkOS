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
using System.Text;
using ModelContextProtocol.Protocol;

try
{
    return await RunAsync();
}
catch (Exception failure)
{
    Console.Error.WriteLine(TerminalText(failure.ToString()));
    return 1;
}

static async Task<int> RunAsync()
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
    // Keep line allocation bounded before handing bytes to the SDK parser.
    await using var server = new BoundedStdioServer();

    // CreateAsync performs the MCP initialize handshake.
    await using var client = await McpClient.CreateAsync(server.Transport, cancellationToken: deadline.Token);

    var tools = await ListToolsBoundedAsync(client, deadline.Token);
    var names = tools.Select(t => t.Name).OrderBy(n => n).ToArray();
    Console.WriteLine($"Lightwork exposes {tools.Count} tools: {string.Join(", ", names.Select(TerminalText))}");
    foreach (var expected in new[] { "maverick_start", "maverick_status", "maverick_facts_get" })
    {
        if (!names.Contains(expected))
        {
            Console.Error.WriteLine($"MCP server is missing tool '{expected}'");
            return 1;
        }
    }

    // A no-LLM round-trip: maverick_facts_get just reads the persistent world model.
    var res = await client.CallToolAsync("maverick_facts_get", cancellationToken: deadline.Token);
    if (res.IsError == true)
    {
        Console.Error.WriteLine("maverick_facts_get reported a tool error");
        return 1;
    }
    if (res.Content.Count == 0)
    {
        Console.Error.WriteLine("maverick_facts_get returned no content");
        return 1;
    }
    Console.WriteLine("maverick_facts_get round-trip OK");

    if (res.StructuredContent is not { } structured ||
        structured.ValueKind != JsonValueKind.Object ||
        !structured.TryGetProperty("facts", out var facts) ||
        facts.ValueKind != JsonValueKind.Object)
    {
        Console.Error.WriteLine(
            "maverick_facts_get returned no structuredContent with a 'facts' object");
        return 1;
    }
    Console.WriteLine("maverick_facts_get structuredContent OK");

    Console.WriteLine("OK: C# client drove Lightwork over MCP end-to-end");
    return 0;
}

static async Task<List<Tool>> ListToolsBoundedAsync(McpClient client, CancellationToken cancellationToken)
{
    List<Tool> tools = [];
    HashSet<string> cursors = [];
    string? cursor = null;
    int remainingBytes = 16 * 1024 * 1024;
    for (int page = 0; page < 100; page++)
    {
        var result = await client.ListToolsAsync(new ListToolsRequestParams { Cursor = cursor }, cancellationToken);
        if (result.Tools.Count > 10_000 - tools.Count)
            throw new InvalidOperationException("MCP tool list exceeds the example's size limit");
        int bytes = JsonSerializer.SerializeToUtf8Bytes(result).Length;
        if (bytes > remainingBytes)
            throw new InvalidOperationException("MCP tool catalog exceeds the example's byte limit");
        remainingBytes -= bytes;
        tools.AddRange(result.Tools);
        cursor = result.NextCursor;
        if (cursor is null) return tools;
        if (!cursors.Add(cursor))
            throw new InvalidOperationException("MCP tool list repeated a pagination cursor");
    }
    throw new InvalidOperationException("MCP tool list exceeds the example's page limit");
}

static string TerminalText(string text)
{
    StringBuilder safe = new();
    int limit = Math.Min(text.Length, 4096);
    foreach (char value in text.AsSpan(0, limit))
    {
        if (value >= ' ' && value <= '~') safe.Append(value);
        else safe.Append("\\u").Append(((int)value).ToString("x4"));
    }
    if (text.Length > limit) safe.Append("... [display truncated]");
    return safe.ToString();
}
