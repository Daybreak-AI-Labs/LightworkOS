// Runnable Java/JVM MCP client for Lightwork.
//
// The executable version of docs/clients/java-quickstart.md and the CI smoke
// for the JVM cross-language surface. It spawns `maverick mcp` (stdio JSON-RPC)
// and runs the documented client flow:
//
//   initialize  ->  tools/list  ->  a no-LLM tools/call (maverick_facts_get)
//
// It deliberately does NOT call maverick_start: that runs the swarm and needs a
// provider key + budget, so it isn't suitable for an unattended CI check.
//
// Run locally:  mvn -q compile exec:java
package ai.cday.maverick.examples;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.ServerParameters;
import io.modelcontextprotocol.client.transport.StdioClientTransport;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.json.McpJsonMapperSupplier;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.ListToolsResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.UUID;
import java.util.stream.Collectors;

public final class Client {

    public static void main(String[] args) throws Exception {
        // The SDK serializes JSON-RPC through an McpJsonMapper, discovered via
        // the McpJsonMapperSupplier SPI (mcp-json-jackson3 provides the default).
        McpJsonMapper json = ServiceLoader.load(McpJsonMapperSupplier.class)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "No McpJsonMapper on the classpath (expected mcp-json-jackson3)"))
                .get();

        // Spawn `maverick mcp` below a uniquely tagged launcher. The SDK keeps
        // its Process private; the tag gives fail-safe cleanup an exact,
        // session-specific transport subtree without reflection.
        String ownershipToken = TaggedMcpLauncher.TOKEN_PREFIX + UUID.randomUUID();
        try (McpProcessOwnership ownership = McpProcessOwnership.create(ownershipToken)) {
            ServerParameters server = taggedServer(ownershipToken, ownership.registry());
            StdioClientTransport transport = new StdioClientTransport(server, json);

            McpSyncClient client = McpClient.sync(transport)
                    .clientInfo(new io.modelcontextprotocol.spec.McpSchema.Implementation(
                            "maverick-java-example", "0.1.0"))
                    .requestTimeout(Duration.ofSeconds(30))
                    .build();

            try (McpClientCleanup cleanup = McpClientCleanup.manage(client, ownership)) {
                client.initialize(); // performs the MCP initialize handshake

                ListToolsResult tools = client.listTools();
                List<String> names = tools.tools().stream().map(Tool::name).sorted()
                        .collect(Collectors.toList());
                System.out.printf("Lightwork exposes %d tools: %s%n",
                        names.size(), String.join(", ", names));

                List<String> missing = new ArrayList<>();
                for (String expected : List.of(
                        "maverick_start", "maverick_status", "maverick_facts_get")) {
                    if (!names.contains(expected)) {
                        missing.add(expected);
                    }
                }
                if (!missing.isEmpty()) {
                    throw new IllegalStateException("MCP server is missing tool(s): " + missing);
                }

                // A no-LLM round-trip: maverick_facts_get just reads the world model.
                CallToolResult res = client.callTool(
                        new CallToolRequest("maverick_facts_get", Map.of()));
                if (res.content() == null || res.content().isEmpty()) {
                    throw new IllegalStateException("maverick_facts_get returned no content");
                }
                System.out.println("maverick_facts_get round-trip OK");

                // Every Lightwork tool also returns structuredContent: typed JSON
                // matching the tool's outputSchema, so a typed client reads parsed
                // fields instead of re-parsing the text block.
                if (!(res.structuredContent() instanceof Map<?, ?> structured)
                        || !structured.containsKey("facts")) {
                    throw new IllegalStateException(
                            "maverick_facts_get returned no structuredContent with 'facts'");
                }
                System.out.println("maverick_facts_get structuredContent OK");
            }
        }

        System.out.println("OK: Java client drove Lightwork over MCP end-to-end");
    }

    private static ServerParameters taggedServer(String ownershipToken, Path ownershipRegistry) {
        String executable = Path.of(
                System.getProperty("java.home"),
                "bin",
                isWindows() ? "java.exe" : "java").toString();
        try {
            String classpath = Path.of(
                    TaggedMcpLauncher.class.getProtectionDomain()
                            .getCodeSource().getLocation().toURI()).toString();
            return ServerParameters.builder(executable)
                    .args(
                            "-cp",
                            classpath,
                            TaggedMcpLauncher.class.getName(),
                            ownershipToken,
                            ownershipRegistry.toString())
                    .build();
        } catch (Exception failure) {
            throw new IllegalStateException("Unable to locate the tagged MCP launcher", failure);
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows");
    }

    private Client() {
    }
}
