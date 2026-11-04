# maverick-installer

The interactive setup wizard. Until the Lightwork distribution names are
reserved and protected on public PyPI, install it from the same pinned source
checkout as the kernel:

```bash
pip install -e ./packages/maverick-core
pip install -e ./apps/installer-cli
maverick init
```

A standalone `maverick-init` entry point is also exposed (same flags).

## Modes

`maverick init` first asks how you want to set up:

- **consumer** (default) — four questions (name, API key, working
  directory, budget) with safe defaults. About a minute. This is what
  the desktop GUI installer runs too, via the same code path.
- **advanced** — pick every provider and per-role model, channels,
  safety profile, sandbox backend, budget, capabilities, web search,
  MCP servers, plugins, tool ACLs, rate limits, retention, persona,
  and notifications.

## Flags

```bash
maverick init --fast     # skip every prompt; write recommended defaults
maverick init --resume   # resume an advanced run from the last unanswered question
```

Both flags work via `maverick init` and the standalone `maverick-init`.

## Output

Writes `~/.maverick/config.toml` (0o600) and, when you enter any keys,
`~/.maverick/.env` (0o600). The agent reads from there. Re-running the
wizard overwrites both.
