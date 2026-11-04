# Lightwork from Java / JVM

Drive a locally running Lightwork swarm from a JVM app (Java, Kotlin,
Scala) over the [Model Context Protocol](https://modelcontextprotocol.io/).
Same contract every IDE-side MCP client uses — you talk to `maverick mcp`
over stdio JSON-RPC.

This is the official cross-language surface. We don't ship a separate
`maverick-jvm` port; we ship one Python kernel and you talk to it from
any language an MCP SDK exists in.

## Prereqs

```bash
# From the root of a source clone (or install Lightwork with the native installer):
python -m pip install -e ./packages/maverick-core -e ./packages/maverick-mcp
```

Add the official [Java MCP SDK](https://github.com/modelcontextprotocol/java-sdk)
(`io.modelcontextprotocol.sdk:mcp`) to your build — pin the version for
reproducibility. The 1.1.3 SDK POM fixes its Jackson cohort at 3.0.3, so import
the patched Jackson 3.1 LTS BOM in the application build:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>tools.jackson</groupId>
      <artifactId>jackson-bom</artifactId>
      <version>3.1.7</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>

<dependency>
  <groupId>io.modelcontextprotocol.sdk</groupId>
  <artifactId>mcp</artifactId>
  <version>1.1.3</version>
</dependency>
```

(Gradle: add `implementation(platform("tools.jackson:jackson-bom:3.1.7"))`,
then `implementation("io.modelcontextprotocol.sdk:mcp:1.1.3")`.)
The checked example and CI use JDK 21. Set your provider key the same way the CLI expects
(e.g. `export ANTHROPIC_API_KEY=…`).

## Quickstart

```java
// Client.java — JDK 21
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.ServerParameters;
import io.modelcontextprotocol.client.transport.StdioClientTransport;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.json.McpJsonMapperSupplier;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.ListToolsResult;
import java.util.Map;
import java.util.ServiceLoader;

public class Client {
    public static void main(String[] args) {
        // The default JSON mapper ships in mcp-json-jackson3 (SPI-discovered).
        McpJsonMapper json = ServiceLoader.load(McpJsonMapperSupplier.class)
                .findFirst().orElseThrow().get();

        // Spawn `maverick mcp` as a subprocess; the SDK manages its stdio.
        ServerParameters server = ServerParameters.builder("maverick").args("mcp").build();
        McpSyncClient client = McpClient.sync(new StdioClientTransport(server, json)).build();

        client.initialize(); // MCP initialize handshake

        ListToolsResult tools = client.listTools();
        System.out.println("Lightwork exposes " + tools.tools().size() + " tools");

        // maverick_start runs the swarm and returns the final answer (long-running).
        var res = client.callTool(new CallToolRequest(
                "maverick_start", Map.of("title", "Say hello from Java", "max_dollars", 0.25)));
        System.out.println(res.content());

        client.closeGracefully();
    }
}
```

```bash
mvn -q compile exec:java
```

You should see the tool list (10 tools), then the swarm's final answer.

## What works

The MCP server exposes **10 `maverick_*` tools** while the much larger
in-kernel registry stays behind the swarm. The
[registry-backed TypeScript surface table](./typescript-quickstart.md#what-works)
is canonical for names and arguments; it covers goal lifecycle, queued
answers, skills, facts, and governed fleet memory.

## Typed results

Besides the human-readable `res.content()` text, every tool returns
`res.structuredContent()` — typed JSON matching the tool's `outputSchema`
(`maverick_facts_get` → `{ "facts": {…} }`), deserialized to a `Map`:

```java
if (res.structuredContent() instanceof Map<?, ?> structured) {
    Object facts = structured.get("facts");
}
```

The shapes are identical across languages — see the
[TypeScript quickstart](./typescript-quickstart.md) for the full
per-tool table.

## Child environment, CLI config, and vaults

This minimal JVM snippet leaves child-environment handling to the SDK, so
`maverick mcp` inherits the Java process environment. The Python child also
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
  reimplement the orchestrator-proposer-verifier topology in Java;
  spawn goals and let Lightwork run the swarm. The JVM process is the
  *client*, not a worker.
- **Sandbox / kernel features are Python-side.** Backends
  (firecracker, k8s, devcontainer) live in `maverick-core` and are
  not part of the wire protocol.
- **The MCP server is for cross-language clients, not for tunneling
  Lightwork over the public internet.** Pair with your own auth +
  TLS layer if you go remote (see `http_transport.py` in `packages/maverick-mcp/`).

## SDK status

The Java MCP SDK is the official SDK, maintained in collaboration with
Spring AI. Pin the version (this doc uses `1.1.3`) and audit the
dependency. If the SDK API drifts, the wire protocol it speaks does
not — you can also implement the JSON-RPC handshake by hand.

## Why no `maven install maverick-core`?

Thin API clients port well; opinionated frameworks don't. The multi-agent
kernel stays in Python, and every MCP-speaking language, Java and Kotlin
included, can drive it without giving up features. The decision is recorded
under [Language bindings](./README.md#language-bindings).

## See also

- [Runnable example + CI smoke](../../examples/clients/java/) — the executable
  version of this quickstart, run in CI against a live `maverick mcp`.
- [TypeScript client quickstart](./typescript-quickstart.md)
- [Go client quickstart](./go-quickstart.md)
- [Rust client quickstart](./rust-quickstart.md)
- [Language bindings](./README.md#language-bindings)
