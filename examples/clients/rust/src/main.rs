//! Runnable Rust MCP client for Lightwork.
//!
//! The executable version of `docs/clients/rust-quickstart.md` and the CI smoke
//! for the Rust cross-language surface. It spawns `maverick mcp` (stdio
//! JSON-RPC) and runs the documented client flow:
//!
//!     initialize  ->  tools/list  ->  a no-LLM tools/call (maverick_facts_get)
//!
//! It deliberately does NOT call maverick_start: that runs the swarm and needs a
//! provider key + budget, so it isn't suitable for an unattended CI check.
//!
//! Run locally:  cargo run

use anyhow::{bail, Context, Result};
use rmcp::{
    model::CallToolRequestParams,
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
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    println!(
        "Lightwork exposes {} tools: {}",
        tools.len(),
        names.join(", ")
    );
    for expected in ["maverick_start", "maverick_status", "maverick_facts_get"] {
        if !names.contains(&expected) {
            bail!("MCP server is missing tool '{expected}'");
        }
    }

    // A no-LLM round-trip: maverick_facts_get just reads the persistent world model.
    let res = client
        .call_tool(CallToolRequestParams::new("maverick_facts_get"))
        .await?;
    if res.content.is_empty() {
        bail!("maverick_facts_get returned no content");
    }
    println!("maverick_facts_get round-trip OK");

    // Every Lightwork tool also returns structuredContent: typed JSON matching
    // the tool's outputSchema, so a typed client reads parsed fields instead of
    // re-parsing the text block. facts_get -> { facts: {...} }.
    let structured = res
        .structured_content
        .as_ref()
        .context("maverick_facts_get returned no structuredContent")?;
    if structured.get("facts").is_none() {
        bail!("structuredContent is missing the 'facts' key");
    }
    println!("maverick_facts_get structuredContent OK");

    client.cancel().await?;
    println!("OK: Rust client drove Lightwork over MCP end-to-end");
    Ok(())
}
