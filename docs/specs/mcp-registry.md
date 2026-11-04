# MCP server registry

The registry provides discovery of MCP servers. Installing or probing a
registry-supplied server is disabled, because the index does not authenticate
its publisher. Related: [`catalog.md`](./catalog.md).

## 1. Scope

Lightwork *consumes* external MCP servers configured in `[mcp_servers.<name>]`
(stdio via `MCPClient`, remote HTTP via `StreamableHttpMCPClient`).
`maverick mcp-registry browse` lists servers from the configured registry
indexes. Adding a registry entry is refused: a server needs independently
reviewed administrator configuration.

Remote servers authenticate with a static bearer (`auth_token`); OAuth 2.1 is
not supported.

## 2. The registry is a federated catalog

A registry is a self-hostable JSON index served at `<base>/mcp/index.json`,
reusing the generic [`catalog.py`](./catalog.md) infra (fetch + 6h cache +
SSRF-guarded `guarded_urlopen` + https-only + stale-serve + multi-index merge,
earlier index wins). Point `[mcp_registries] indexes` at your own base(s).
Without that setting the built-in default (`DEFAULT_MCP_REGISTRIES`, the same
base as the content catalog) is used; an unreachable or empty index yields no
entries.

```toml
# ~/.maverick/config.toml
[mcp_registries]
indexes = ["https://registry.example.com/catalog", "https://internal.acme/catalog"]
```

## 3. Index schema (`<base>/mcp/index.json`)

```json
{
  "schema_version": 1,
  "kind": "mcp",
  "entries": [
    {
      "name": "github",
      "version": "1.0.0",
      "summary": "GitHub MCP server (issues, PRs, code search).",
      "author": "modelcontextprotocol",
      "verified": true,
      "spec": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-github"],
        "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
        "pin_sha256": "<optional: hash of the resolved executable>"
      }
    },
    {
      "name": "acme-remote",
      "version": "2.0.0",
      "summary": "Acme's hosted MCP server.",
      "spec": {"url": "https://mcp.acme.com/sse", "headers": {"X-Tenant": "acme"}}
    }
  ]
}
```

**Why the spec is inline (vs. skills' fetched `SKILL.md` + `sha256`).** An MCP
server's installable artifact is *configuration*, not a content file. There's
nothing to fetch and hash — the actual server binary is resolved at spawn time
(`npx`/`pip`/a URL). So the entry carries the `spec` (a `[mcp_servers.<name>]`
dict) directly, and `source`/`sha256` are optional. `CatalogEntry` has an
optional `spec: dict` field for this; content kinds (skills, personas) leave it
empty and fetch `source`.

## 4. Trust model

- The index is **curated** (a PR against the registry repo adds an entry) and
  served over **https** through the SSRF guard.
- `verified` is **self-asserted by the index** and is NOT a trust signal (the
  index host is unauthenticated), exactly as in `catalog.md`.
- `pin_sha256` checks the selected executable's bytes. It does not authenticate
  arguments, loaded files, child executables, or an untrusted registry's choice
  of executable. Registry-supplied local commands are therefore refused.
- Registry entries cannot be installed or probed; schema validation alone does
  not authenticate their endpoint or executable.
- A directly configured local server still needs independent review and a
  suitable OS isolation boundary before it runs.

## 5. Code

`packages/maverick-core/maverick/mcp_registry.py`:

- `load_mcp_registry()` / `resolve_mcp(name)` → `catalog.load_catalog("mcp", …)`
  with the `[mcp_registries] indexes`.
- `spec_from_entry(entry)` and `install_mcp_from_registry(name)` refuse
  unauthenticated registry-provided configuration.
- `add_mcp_server_to_config(name, spec_dict)` / `remove_mcp_server_from_config(name)`
  — dependency-free TOML mutation (append the one table on add; text-scan removal
  on remove) so the rest of a hand-edited `config.toml` — comments, ordering,
  unrelated tables — is preserved. (`tomli_w` is not a dependency; Python ships no
  stdlib TOML writer.)

`MCPServerSpec.to_dict()` (in `mcp_client.py`) is the inverse of `from_config`,
used to serialize a resolved spec into config.

## 6. CLI

`maverick mcp-registry` (a group distinct from `maverick mcp`, which starts
Lightwork's *own* server):

- `browse` — list registry servers (name, version, transport, verified badge).
- `add <name>` — refuses unauthenticated registry entries.
- `remove <name>` — drop the table from config.
- `list` — show the MCP servers currently configured (via the kernel's loader).

## 7. Config knob + wizard (kernel rules 5 and 6)

- Knob: `[mcp_registries] indexes` (list of base URLs). Without it, discovery
  uses the built-in default, so the knob is only for custom/self-hosted
  registries.
- Wizard: `write_config` emits `[mcp_registries]` when custom indexes are
  supplied, so the installer can write the knob; it's omitted by default to keep
  the config minimal.

## 8. Limits

- Remote servers support static bearer authentication only, not OAuth 2.1.
- Registry entries are unsigned, so neither their authenticity nor a complete
  workload authorization can be established from the index.
- The schema carries `install_count`, but the CLI does not rank or display it.

## 9. Local command trust

The registry may describe local stdio servers for discovery, but installation
and probing of registry-supplied local commands are disabled: pinning an
executable does not authenticate its arguments or additional programs it may
run. An administrator can independently review and configure a local MCP
server directly. HTTP registry entries are also unavailable for installation
or probing, because their publisher and full configuration are not authenticated.
