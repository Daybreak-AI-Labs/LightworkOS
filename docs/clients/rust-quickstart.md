# Lightwork from Rust

Drive a locally running Lightwork swarm from Rust over the
[Model Context Protocol](https://modelcontextprotocol.io/). Same
contract every IDE-side MCP client uses — you talk to `maverick mcp`
over stdio JSON-RPC.

We don't ship a separate `maverick-rs` crate; you talk to the Python
kernel via the official [Rust MCP SDK](https://github.com/modelcontextprotocol/rust-sdk)
(the `rmcp` crate).

## Prereqs

```bash
# From the root of a source clone (or install Lightwork with the native installer):
python -m pip install -e ./packages/maverick-core -e ./packages/maverick-mcp
# Official Rust MCP SDK; pin a published version for reproducible builds.
# The client role and the child-process stdio transport are not on by default.
cargo add rmcp@2.0.0 --features client,transport-child-process
cargo add tokio --features macros,rt-multi-thread,process,io-util
cargo add serde_json
cargo add anyhow
```

Set `ANTHROPIC_API_KEY` (or whichever provider key the kernel needs).

## Quickstart

```rust
// src/main.rs
use anyhow::Result;
use rmcp::{
    model::CallToolRequestParams,
    object,
    transport::{ConfigureCommandExt, TokioChildProcess},
    ServiceExt,
};
use tokio::process::Command;

#[tokio::main]
async fn main() -> Result<()> {
    // Spawn `maverick mcp` as a child process; rmcp wires up stdio JSON-RPC and
    // performs the MCP initialize handshake. `()` is the (no-op) client handler.
    let client = ()
        .serve(TokioChildProcess::new(Command::new("maverick").configure(
            |cmd| {
                cmd.arg("mcp");
            },
        ))?)
        .await?;

    let tools = client.list_all_tools().await?;
    println!("Lightwork exposes {} tools", tools.len());

    // maverick_start runs the swarm and returns the final answer (long-running).
    let res = client
        .call_tool(
            CallToolRequestParams::new("maverick_start")
                .with_arguments(object!({ "title": "Say hello from Rust", "max_dollars": 0.25 })),
        )
        .await?;
    for content in &res.content {
        if let Some(text) = content.as_text() {
            println!("{}", text.text);
        }
    }

    client.cancel().await?;
    Ok(())
}
```

```bash
cargo run --release
```

## Typed results

Besides the human-readable `res.content` text, every tool returns
`res.structured_content: Option<Value>` — typed JSON matching the
tool's `outputSchema` (`maverick_facts_get` → `{ "facts": {…} }`):

```rust
if let Some(structured) = &res.structured_content {
    let facts = structured.get("facts");
    let _ = facts;
}
```

The shapes are identical across languages — see the
[TypeScript quickstart](./typescript-quickstart.md) for the full
per-tool table.

## Child environment, CLI config, and vaults

This minimal Rust snippet does not clear or replace the Tokio command
environment, so `maverick mcp` inherits the Rust process environment. The
Python child also loads the same CLI `config.toml`, dashboard/tenant settings,
secret-provider files, and enabled vaults; credentials are resolved there, not
sent as MCP arguments. For production, apply the
[reviewed filtered-environment policy](./typescript-quickstart.md#child-environment-cli-config-and-vaults)
used by the runnable TypeScript example.

## Why no `maverick-rs` crate?

Same reason there's no `maverick-go` or `maverick-ts`: the multi-agent kernel
stays in Python, and a port would duplicate it without adding reach. See
[Language bindings](./README.md#language-bindings).

Rust is the natural language for *embedders* — CLI tools and
infrastructure agents that need a small binary footprint and don't
want to ship a Python interpreter. The right Rust unit is a thin
**RPC client** that drives the Python kernel, not a re-implementation.

## SDK status

`rmcp` is the official Rust MCP SDK from the Model Context Protocol
project. It's async (tokio) and ships a child-process stdio transport
(`TokioChildProcess`) plus the client role behind feature flags. Pin a
specific version and enable only the features you need; if the API
drifts across releases, the wire protocol it speaks does not.

## See also

- [Runnable example + CI smoke](../../examples/clients/rust/) — the executable
  version of this quickstart, run in CI against a live `maverick mcp`.
- [TypeScript client quickstart](./typescript-quickstart.md)
- [Go client quickstart](./go-quickstart.md)
- [C# / .NET client quickstart](./csharp-quickstart.md)
- [Java / JVM client quickstart](./java-quickstart.md)
- [Language bindings](./README.md#language-bindings)
