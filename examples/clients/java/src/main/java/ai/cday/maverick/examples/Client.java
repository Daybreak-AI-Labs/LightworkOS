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
import io.modelcontextprotocol.spec.McpSchema.JSONRPCMessage;
import io.modelcontextprotocol.spec.McpSchema.JSONRPCNotification;
import reactor.core.publisher.Mono;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class Client {

    public static void main(String[] args) throws Exception {
        try {
            run();
        } catch (Exception failure) {
            // SDK errors can include text supplied by the server. Do not hand
            // that text to the terminal's control-sequence interpreter.
            java.io.StringWriter details = new java.io.StringWriter();
            failure.printStackTrace(new java.io.PrintWriter(details));
            System.err.println(terminalText(details.toString()));
            System.exit(1);
        }
    }

    private static void run() throws Exception {
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
            BoundedCatalogTransport transport = new BoundedCatalogTransport(server, json);
            transport.setStdErrorHandler(line -> System.err.println(terminalText(line)));

            McpSyncClient client = McpClient.sync(transport)
                    .clientInfo(new io.modelcontextprotocol.spec.McpSchema.Implementation(
                            "maverick-java-example", "0.1.0"))
                    .requestTimeout(Duration.ofSeconds(30))
                    .build();

            try (McpClientCleanup cleanup = McpClientCleanup.manage(client, ownership)) {
                client.initialize(); // performs the MCP initialize handshake

                List<String> names = listToolsBounded(client, json).stream().map(Tool::name).sorted()
                        .collect(Collectors.toList());
                System.out.printf("Lightwork exposes %d tools: %s%n",
                        names.size(), names.stream().map(Client::terminalText)
                                .collect(Collectors.joining(", ")));

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
                if (Boolean.TRUE.equals(res.isError())) {
                    throw new IllegalStateException("maverick_facts_get reported a tool error");
                }
                if (res.content() == null || res.content().isEmpty()) {
                    throw new IllegalStateException("maverick_facts_get returned no content");
                }
                System.out.println("maverick_facts_get round-trip OK");

                // Every Lightwork tool also returns structuredContent: typed JSON
                // matching the tool's outputSchema, so a typed client reads parsed
                // fields instead of re-parsing the text block.
                if (!(res.structuredContent() instanceof Map<?, ?> structured)
                        || !(structured.get("facts") instanceof Map<?, ?>)) {
                    throw new IllegalStateException(
                            "maverick_facts_get returned no structuredContent with a 'facts' object");
                }
                System.out.println("maverick_facts_get structuredContent OK");
            } catch (Exception failure) {
                transport.requireNoAutomaticRefresh();
                throw failure;
            }
            transport.requireNoAutomaticRefresh();
        }

        System.out.println("OK: Java client drove Lightwork over MCP end-to-end");
    }

    private static final class BoundedCatalogTransport extends StdioClientTransport {
        private final AtomicReference<IllegalStateException> refusal = new AtomicReference<>();

        BoundedCatalogTransport(ServerParameters server, McpJsonMapper json) {
            super(server, json);
        }

        @Override
        public Mono<Void> connect(Function<Mono<JSONRPCMessage>, Mono<JSONRPCMessage>> handler) {
            // The SDK automatically fetches complete catalogs on these
            // notifications, bypassing the explicit bounded page reader.
            return super.connect(message -> handler.apply(message.filter(this::admitMessage)));
        }

        private boolean admitMessage(JSONRPCMessage message) {
            if (message instanceof JSONRPCNotification notification
                    && List.of("notifications/tools/list_changed",
                            "notifications/resources/list_changed",
                            "notifications/prompts/list_changed").contains(notification.method())) {
                refusal.compareAndSet(null, new IllegalStateException(
                        "MCP automatic catalog refresh is unsupported by this bounded example"));
                return false;
            }
            return true;
        }

        @Override
        public Mono<Void> sendMessage(JSONRPCMessage message) {
            IllegalStateException failure = refusal.get();
            return failure == null ? super.sendMessage(message) : Mono.error(failure);
        }

        void requireNoAutomaticRefresh() {
            IllegalStateException failure = refusal.get();
            if (failure != null) throw failure;
        }
    }

    private static List<Tool> listToolsBounded(McpSyncClient client, McpJsonMapper json) throws Exception {
        List<Tool> tools = new ArrayList<>();
        HashSet<String> cursors = new HashSet<>();
        String cursor = null;
        int remainingBytes = 16 * 1024 * 1024;
        for (int page = 0; page < 100; page++) {
            ListToolsResult result = client.listTools(cursor);
            if (result.tools().size() > 10_000 - tools.size()) {
                throw new IllegalStateException("MCP tool list exceeds the example's size limit");
            }
            int bytes = json.writeValueAsBytes(result).length;
            if (bytes > remainingBytes) {
                throw new IllegalStateException("MCP tool catalog exceeds the example's byte limit");
            }
            remainingBytes -= bytes;
            tools.addAll(result.tools());
            cursor = result.nextCursor();
            if (cursor == null || cursor.isEmpty()) {
                return tools;
            }
            if (!cursors.add(cursor)) {
                throw new IllegalStateException("MCP tool list repeated a pagination cursor");
            }
        }
        throw new IllegalStateException("MCP tool list exceeds the example's page limit");
    }

    private static String terminalText(String text) {
        StringBuilder safe = new StringBuilder();
        int limit = Math.min(text.length(), 4096);
        for (int i = 0; i < limit; i++) {
            char value = text.charAt(i);
            if (value >= ' ' && value <= '~') {
                safe.append(value);
            } else {
                safe.append(String.format("\\u%04x", (int) value));
            }
        }
        if (text.length() > limit) {
            safe.append("... [display truncated]");
        }
        return safe.toString();
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
