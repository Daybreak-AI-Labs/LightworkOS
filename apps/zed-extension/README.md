# maverick-zed-extension

Drive the [Lightwork](https://github.com/Daybreak-AI-Labs/LightworkOS) agent runtime
from the [Zed](https://zed.dev) editor. Two surfaces:

1. **Assistant context server (MCP).** The extension registers
   `maverick mcp` — Lightwork's official MCP server
   (`packages/maverick-mcp`, stdio transport) — as a Zed context server, so
   Zed's assistant can start goals, check status, and read results through
   MCP tools.
2. **Terminal tasks.** `tasks/maverick.json` ships ready-made Zed tasks for
   the CLI verbs that actually exist in `maverick/cli.py`: `status`,
   `monitor`, `runs`, `budget`, `doctor`, `start`, `halt`, `unhalt`. Copy
   them into `.zed/tasks.json` (project) or `~/.config/zed/tasks.json`
   (global) and run via `task: spawn`.

## Why tasks and not slash commands for the CLI verbs

Zed extensions are Rust compiled to **WASM running in a WASI sandbox**: the
extension code cannot spawn processes, so a slash command implemented in
`src/lib.rs` cannot shell out to `maverick status`. The only extension hook
that results in a real local process is the context-server hook, where the
extension returns a command **and Zed spawns it** — that is exactly what
`src/lib.rs` does with `maverick mcp`. Everything terminal-shaped is
delivered as tasks, which Zed runs in its own terminal. The split follows
what the extension sandbox actually allows.

## Prerequisites

- The `maverick` CLI installed and on PATH, with the MCP server package:
  from a Lightwork checkout, run
  `pip install -e ./packages/maverick-core -e ./packages/maverick-mcp` (or use
  the pinned-source installers under `apps/` / `deploy/`). Lightwork packages
  are not published on PyPI; install from source.
- Zed (stable) with assistant/context-server support.

## Building and qualification

**Preview:** the pinned Rust1.97.1 / `wasm32-wasip2` / API0.7.0 build and source
bundle are supplied in [BUILDING.md](BUILDING.md). Run `python build.py` to compile
the locked dependencies and produce an unsigned archive with the WASM component,
source and checksum manifest. The source compiles with the pinned toolchain; no installed Zed
host, authenticated MCP session or accessibility qualification is claimed.

An end-user marketplace release still requires the release owner's selected
host matrix, distribution approval and installed-host evidence. For development,
Zed's **Install Dev Extension** loads the source directory and builds it. The
extension never installs the Lightwork CLI; `maverick` must already be on PATH.
