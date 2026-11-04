# Lightwork content catalog (federated)

A catalog lets users browse and install community skills without editing
config or running install-by-URL. It's the dashboard **Store** tab and the
`maverick skill browse` / `maverick skill add` commands. The index format also
carries other kinds (plugins, MCP servers, personas); only skills have an
install path, and MCP servers are covered by the
[MCP server registry](./mcp-registry.md).

## Index format

One `index.json` per kind, served at `<base>/<kind>/index.json`:

```json
{
  "schema_version": 1,
  "kind": "skills",
  "entries": [
    {
      "name": "summarize-url",
      "version": "1.0.0",
      "summary": "Fetch a URL and write a 3-sentence summary.",
      "source": "gh:org/repo:path/to/SKILL.md",
      "sha256": "<hex digest of the fetched content>",
      "author": "org",
      "verified": true,
      "install_count": 0
    }
  ]
}
```

A worked example lives in [`catalog-example/`](./catalog-example/).

## Trust model

Catalog skill installation requires a valid Ed25519 signature from a publisher
whose public key is configured in `[skills].trusted_pubkeys`. No publisher key
is bundled, so an administrator must configure one before installing catalog
skills. The index hash checks the downloaded bytes but does not authenticate
them when the same host controls the index and content. Shield scanning is an
additional best-effort check, not a guarantee against malicious instructions.

Free-text `POST /api/v1/skills` (arbitrary `gh:`/`https:` source) stays
gated behind `MAVERICK_ALLOW_SKILL_INSTALL=1` — that's the RCE vector.
`POST /api/v1/catalog/skills/install` resolves by name and requires both the
hash and a trusted signature. MCP catalog specs have separate trust limits.

## Configuration

```toml
[catalogs]
# Base URLs (no trailing /kind). Multiple indexes merge; earlier wins
# on name collision. Without this setting the built-in default index is
# used; an unreachable or empty index yields no entries.
indexes = ["https://raw.githubusercontent.com/your-org/your-index/main/catalog"]
```

Self-hosting an index is just serving static `index.json` files — a
GitHub Pages repo or any HTTPS static host. No server code required.

## Caching

Indexes cache to `~/.maverick/cache/catalog/` for 6 hours. An
unreachable index degrades to "no entries" (it never breaks the
dashboard) and serves a stale cache if one exists.

## Surfaces

- Dashboard: `/store` (Store tab) + `GET /api/v1/catalog/{kind}` +
  `POST /api/v1/catalog/skills/install`
- CLI: `maverick skill browse`, `maverick skill add <name>`

## Limits

- Only skills can be installed from a catalog.
- The `verified` field is set by the index, not derived from a publisher
  signature, so it is not a trust signal.
- `install_count` is reported by the index; the client does not increment it.
