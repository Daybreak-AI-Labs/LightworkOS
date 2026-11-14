# maverick-mcp-server

A Model Context Protocol (MCP) server that exposes Lightwork's agent
loop as a set of MCP tools. Any MCP-compatible client (Claude Code,
Claude Desktop, Cursor, etc.) can drive Lightwork over stdio JSON-RPC.

## Why

Lightwork is a swarm of agents with persistent memory, budget caps,
and verifier loops. Most MCP clients are single-turn. By plugging
Lightwork in via MCP, you get:

- A "think hard for an hour" tool from inside Claude Code
- Persistent goals that survive editor restarts
- Per-role model routing controlled by your `~/.maverick/config.toml`
- Auto-distilled skills that compound across sessions

## Install

Installed by
[Install from source](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/source-install.md).
For development on this package alone:

```bash
python -m pip install -e ./packages/maverick-core -e ./packages/maverick-mcp
```

## Wire into Claude Code

Add to your Claude Code MCP config (typically
`~/.config/claude-code/mcp.json` or similar):

```json
{
  "mcpServers": {
    "maverick": {
      "command": "maverick-mcp",
      "args": []
    }
  }
}
```

Then restart Claude Code. The Lightwork tools should appear under the
MCP servers menu.

Each MCP start or resume attempt defaults to a $2 spend cap and a 1,800-second
wall-clock cap when no operator ceiling is configured. Operators can set
`MAVERICK_MCP_MAX_DOLLARS` and `MAVERICK_MCP_MAX_WALL_SECONDS` (or the
corresponding `[mcp]` settings); stricter configured and authenticated-agent
trust-registry budgets also apply.

Network MCP callers, including clients using the shared HTTP bearer, cannot
read or write the tenant-wide fact store, and those tools are omitted from their
tool listings. Facts remain available to local
operator integrations; network callers' goals also do not receive those facts
as standing context.
These are per-attempt limits, not a shared limit across concurrent calls or
elicitation resumes. Configure an organization budget for aggregate spending.

## Tools exposed

| Tool | What it does |
|---|---|
| `maverick_start` | Start a new goal, run the swarm, return the final answer |
| `maverick_status` | List recent goals + open questions |
| `maverick_resume` | Resume a paused goal |
| `maverick_answer` | Answer a queued question |
| `maverick_skill_install` | Install a SKILL.md from URL or gh:org/repo when `MAVERICK_ALLOW_SKILL_INSTALL=1` (local paths are rejected) |
| `maverick_skills_list` | List installed / distilled skills |
| `maverick_fact_set` | Set a fact in the world model |
| `maverick_facts_get` | Get all known facts |
| `maverick_fleet_ingest` | Deposit a governed lesson into fleet memory (`[fleet_memory] enable`) |
| `maverick_fleet_recall` | Recall governed lessons from fleet memory (`[fleet_memory] enable`) |

All calls go through `maverick.orchestrator.run_goal` -- same Shield
chokepoints, same budget caps, same per-role model routing.

## Protocol

Minimal JSON-RPC 2.0 over stdio (`lightwork mcp`) or streamable HTTP
(`lightwork mcp --http`), matching the MCP 2025-11-25 spec (with a
2024-11-05 fallback). Stdio has no external dependencies; the HTTP
transport needs the `[http]` extra (FastAPI + uvicorn).
HTTP initialization returns a caller-bound `Mcp-Session-Id`; clients should send
it on subsequent requests so request IDs and cancellation remain scoped to that
client across connections. Without a session, request IDs are scoped to the
bearer credential, so sessionless clients sharing a bearer share one request-ID
namespace and can cancel each other's requests.
Failed HTTP bearer attempts are limited per network peer. Callers behind the
same proxy share that failure budget; configure an upstream limiter when they
need independent quotas. Lightwork's launcher preserves the socket peer; an
external ASGI server must also disable proxy-header rewriting for this limit.
The server is hand-rolled rather than built on the full `mcp` Python SDK,
which keeps the dependency footprint tiny.
