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
    model::{CallToolRequestParams, PaginatedRequestParams, Tool},
    transport::{ConfigureCommandExt, TokioChildProcess},
    Peer, RoleClient, ServiceExt,
};
use std::{collections::HashSet, process::ExitCode, time::Duration};
use tokio::process::Command;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {}", terminal_text(&format!("{error:#}")));
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    // Spawn `maverick mcp` as a child process; rmcp wires up stdio JSON-RPC and
    // performs the MCP initialize handshake. `()` is the (no-op) client handler.
    let startup = ().serve(TokioChildProcess::new(Command::new("maverick").configure(
        |cmd| {
            // Initialization can fail before a RunningService exists.
            // Its drop-time cleanup must also survive runtime shutdown.
            cmd.arg("mcp").kill_on_drop(true);
        },
    ))?);
    let client = tokio::time::timeout(Duration::from_secs(30), startup)
        .await
        .context("MCP initialization exceeded 30 seconds")??;

    let result = tokio::time::timeout(Duration::from_secs(30), check_client(&client))
        .await
        .context("MCP tool checks exceeded 30 seconds")
        .and_then(|result| result);
    // Await cleanup on refusals too, before the Tokio runtime is torn down.
    let cleanup = client.cancel().await;
    result?;
    cleanup?;
    println!("OK: Rust client drove Lightwork over MCP end-to-end");
    Ok(())
}

async fn check_client(client: &Peer<RoleClient>) -> Result<()> {
    let tools = list_tools_bounded(client).await?;
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    println!(
        "Lightwork exposes {} tools: {}",
        tools.len(),
        names
            .iter()
            .map(|name| terminal_text(name))
            .collect::<Vec<_>>()
            .join(", ")
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
    if res.is_error == Some(true) {
        bail!("maverick_facts_get reported a tool error");
    }
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
    if !structured
        .get("facts")
        .is_some_and(|facts| facts.is_object())
    {
        bail!("structuredContent is missing a 'facts' object");
    }
    println!("maverick_facts_get structuredContent OK");

    Ok(())
}

async fn list_tools_bounded(client: &Peer<RoleClient>) -> Result<Vec<Tool>> {
    let mut tools = Vec::new();
    let mut cursors = HashSet::new();
    let mut cursor = None;
    let mut remaining_bytes = 16 * 1024 * 1024;
    for _ in 0..100 {
        let mut params = PaginatedRequestParams::default();
        params.cursor = cursor;
        let page = client.list_tools(Some(params)).await?;
        if page.tools.len() > 10_000 - tools.len() {
            bail!("MCP tool list exceeds the example's size limit");
        }
        let bytes = rmcp::serde_json::to_vec(&page)?.len();
        if bytes > remaining_bytes {
            bail!("MCP tool catalog exceeds the example's byte limit");
        }
        remaining_bytes -= bytes;
        tools.extend(page.tools);
        cursor = page.next_cursor;
        match &cursor {
            None => return Ok(tools),
            Some(next) if !cursors.insert(next.clone()) => {
                bail!("MCP tool list repeated a pagination cursor");
            }
            _ => {}
        }
    }
    bail!("MCP tool list exceeds the example's page limit")
}

fn terminal_text(text: &str) -> String {
    let mut characters = text.chars();
    let mut safe: String = characters
        .by_ref()
        .take(4096)
        .flat_map(char::escape_default)
        .collect();
    if characters.next().is_some() {
        safe.push_str("... [display truncated]");
    }
    safe
}
