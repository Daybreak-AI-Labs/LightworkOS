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
use std::{
    collections::HashSet,
    process::{ExitCode, Stdio},
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    process::{ChildStderr, Command},
    sync::oneshot,
};

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
    let (transport, stderr) =
        TokioChildProcess::builder(Command::new("maverick").configure(|cmd| {
            // Initialization can fail before a RunningService exists.
            // Its drop-time cleanup must also survive runtime shutdown.
            cmd.arg("mcp").kill_on_drop(true);
        }))
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = stderr.context("MCP stderr pipe is unavailable")?;
    let (stderr_sender, stderr_receiver) = oneshot::channel();
    let mut stderr_failure = Some(stderr_receiver);
    let mut stderr_task = tokio::spawn(async move {
        if let Err(error) = drain_stderr(stderr).await {
            let _ = stderr_sender.send(error);
        }
    });
    let mut client = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(30), ().serve(transport)) =>
            result.context("MCP initialization exceeded 30 seconds")??,
        error = wait_stderr_failure(&mut stderr_failure) => return Err(error),
    };

    let mut result = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(30), check_client(&client)) =>
            result.context("MCP tool checks exceeded 30 seconds").and_then(|result| result),
        error = wait_stderr_failure(&mut stderr_failure) => Err(error),
    };
    // Await cleanup on refusals too, before the Tokio runtime is torn down.
    // A nonreading server can hold the SDK writer mutex during close. Bound
    // that wait; kill_on_drop still applies when runtime teardown drops it.
    let cleanup = client.close_with_timeout(Duration::from_secs(2)).await;
    let stderr_cleanup = tokio::time::timeout(Duration::from_secs(2), &mut stderr_task).await;
    if stderr_cleanup.is_err() {
        stderr_task.abort();
    }
    if let Some(mut receiver) = stderr_failure {
        if let Ok(error) = receiver.try_recv() {
            if result.is_ok() {
                result = Err(error);
            }
        }
    }
    result?;
    cleanup?.context("MCP cleanup exceeded 2 seconds")?;
    stderr_cleanup.context("MCP stderr did not close during cleanup")??;
    println!("OK: Rust client drove Lightwork over MCP end-to-end");
    Ok(())
}

async fn wait_stderr_failure(
    receiver: &mut Option<oneshot::Receiver<anyhow::Error>>,
) -> anyhow::Error {
    if let Some(pending) = receiver {
        let error = pending.await.ok();
        *receiver = None;
        if let Some(error) = error {
            return error;
        }
    }
    // A server may close stderr while continuing its protocol exchange.
    std::future::pending().await
}

async fn drain_stderr(mut stderr: ChildStderr) -> Result<()> {
    let mut chunk = [0; 8192];
    let mut line = Vec::new();
    loop {
        let count = stderr.read(&mut chunk).await?;
        if count == 0 {
            if !line.is_empty() {
                eprintln!("{}", terminal_text(&String::from_utf8_lossy(&line)));
            }
            return Ok(());
        }
        for &value in &chunk[..count] {
            if line.len() == 64 * 1024 {
                bail!("MCP stderr line exceeds the transport size limit");
            }
            if value == b'\n' {
                eprintln!("{}", terminal_text(&String::from_utf8_lossy(&line)));
                line.clear();
            } else {
                line.push(value);
            }
        }
    }
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
