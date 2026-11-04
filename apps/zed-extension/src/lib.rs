//! Zed extension for the Lightwork agent runtime.
//!
//! Zed extensions run as WASM in a WASI sandbox: they cannot spawn
//! processes themselves. The one extension hook that launches a real local
//! process is the context-server hook — the extension *returns* a command
//! and Zed spawns it. We use it to register Lightwork's MCP server
//! (`maverick mcp`, stdio transport — packages/maverick-mcp), which is the
//! product's official cross-language surface, so Zed's assistant can drive
//! the swarm: start goals, check status, read results.
//!
//! Terminal-style CLI verbs (`maverick status` / `monitor` / `halt` / ...)
//! cannot be exec'd from sandboxed extension code, so they ship as Zed
//! *tasks* instead: see tasks/maverick.json and the README.

use zed_extension_api::{self as zed, Command, ContextServerId, Project, Result};

struct MaverickExtension;

impl zed::Extension for MaverickExtension {
    fn new() -> Self {
        Self
    }

    fn context_server_command(
        &mut self,
        _context_server_id: &ContextServerId,
        _project: &Project,
    ) -> Result<Command> {
        // `maverick mcp` serves MCP over stdio by default (maverick/cli.py).
        // The CLI must already be installed and on PATH (pipx / pip / the
        // platform installers under apps/ and deploy/); the extension does
        // not install it.
        Ok(Command {
            command: "maverick".to_string(),
            args: vec!["mcp".to_string()],
            env: Vec::new(),
        })
    }
}

zed::register_extension!(MaverickExtension);
