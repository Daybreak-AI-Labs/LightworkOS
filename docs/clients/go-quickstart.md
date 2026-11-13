# Lightwork from Go

Drive a locally running Lightwork swarm from Go over the
[Model Context Protocol](https://modelcontextprotocol.io/). Same
contract every IDE-side MCP client uses — you talk to `maverick mcp`
over stdio JSON-RPC.

We don't ship a separate `maverick-go` package; you talk to the
Python kernel via the standard MCP SDK for Go.

## Prereqs

```bash
# From the root of a source clone (or install Lightwork with the native installer):
python -m pip install -e ./packages/maverick-core -e ./packages/maverick-mcp
go get github.com/modelcontextprotocol/go-sdk@v1.6.1
```

Use Go 1.26.11 or newer so the client inherits the current standard-library
security fixes. Set `ANTHROPIC_API_KEY` (or whichever provider key the kernel
needs).

## Quickstart

```go
// quickstart.go
package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	ctx := context.Background()

	// Start `maverick mcp` as a subprocess; the SDK manages stdio.
	client := mcp.NewClient(&mcp.Implementation{Name: "go-quickstart", Version: "0.1.0"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command("maverick", "mcp")}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Lightwork exposes %d tools\n", len(tools.Tools))

	// maverick_start runs the swarm and returns the final answer (long-running).
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "maverick_start",
		Arguments: map[string]any{"title": "Say hello from Go", "max_dollars": 0.25},
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			fmt.Println(tc.Text)
		}
	}
}
```

```bash
go run quickstart.go
```

## Typed results

Besides the human-readable `res.Content` text, every tool returns
`res.StructuredContent` — typed JSON matching the tool's `outputSchema`
(`maverick_facts_get` → `{ "facts": {…} }`). Type-assert it to read
parsed fields instead of re-parsing prose:

```go
if sc, ok := res.StructuredContent.(map[string]any); ok {
	facts := sc["facts"]
	_ = facts
}
```

The shapes are identical across languages — see the
[TypeScript quickstart](./typescript-quickstart.md) for the full
per-tool table.

## Child environment, CLI config, and vaults

This minimal Go snippet uses `exec.Command` without an explicit `Env`, so
`maverick mcp` inherits the Go process environment. The Python child also loads
the same CLI `config.toml`, dashboard/tenant settings, secret-provider files,
and enabled vaults; credentials are resolved there, not sent as MCP arguments.
For production, apply the
[reviewed filtered-environment policy](./typescript-quickstart.md#child-environment-cli-config-and-vaults)
used by the runnable TypeScript example.

## SDK status

The Go MCP SDK is community-maintained; pin a specific tag and audit
the dependency. If the SDK API drifts, the wire protocol it speaks
does not — you can also implement the JSON-RPC handshake by hand in
~80 lines of Go.

## See also

- [Runnable example + CI smoke](../../examples/clients/go/) — the executable
  version of this quickstart, run in CI against a live `maverick mcp`.
- [TypeScript client quickstart](./typescript-quickstart.md)
- [Rust client quickstart](./rust-quickstart.md)
- [C# / .NET client quickstart](./csharp-quickstart.md)
- [Java / JVM client quickstart](./java-quickstart.md)
- [Language bindings](./README.md#language-bindings)
