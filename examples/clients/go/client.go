// Runnable Go MCP client for Lightwork.
//
// The executable version of docs/clients/go-quickstart.md and the CI smoke for
// the Go cross-language surface. It spawns `maverick mcp` (stdio JSON-RPC) and
// runs the documented client flow:
//
//	initialize  ->  tools/list  ->  a no-LLM tools/call (maverick_facts_get)
//
// It deliberately does NOT call maverick_start: that runs the swarm and needs a
// provider key + budget, so it isn't suitable for an unattended CI check.
//
// Run locally:  go run .
package main

import (
	"context"
	"log"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	ctx := context.Background()

	client := mcp.NewClient(&mcp.Implementation{Name: "maverick-go-example", Version: "0.1.0"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command("maverick", "mcp")}

	session, err := client.Connect(ctx, transport, nil) // performs the MCP initialize handshake
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		log.Fatalf("list tools: %v", err)
	}
	names := make(map[string]bool, len(tools.Tools))
	for _, t := range tools.Tools {
		names[t.Name] = true
	}
	log.Printf("Lightwork exposes %d tools", len(tools.Tools))
	for _, want := range []string{"maverick_start", "maverick_status", "maverick_facts_get"} {
		if !names[want] {
			log.Fatalf("MCP server is missing tool %q", want)
		}
	}

	// A no-LLM round-trip: maverick_facts_get just reads the world model.
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "maverick_facts_get",
		Arguments: map[string]any{},
	})
	if err != nil {
		log.Fatalf("call maverick_facts_get: %v", err)
	}
	if len(res.Content) == 0 {
		log.Fatal("maverick_facts_get returned no content")
	}
	log.Println("maverick_facts_get round-trip OK")

	// Every Lightwork tool also returns structuredContent: typed JSON matching
	// the tool's outputSchema, so a typed client reads parsed fields instead of
	// re-parsing the text block. facts_get -> { facts: {...} }.
	structured, ok := res.StructuredContent.(map[string]any)
	if !ok {
		log.Fatal("maverick_facts_get returned no structuredContent object")
	}
	if _, ok := structured["facts"]; !ok {
		log.Fatal("structuredContent is missing the 'facts' key")
	}
	log.Println("maverick_facts_get structuredContent OK")

	log.Println("OK: Go client drove Lightwork over MCP end-to-end")
}
