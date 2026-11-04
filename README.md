<p align="center">
  <img src="docs/assets/daybreak-labs-logo.jpg" alt="Daybreak Labs" width="360">
</p>

# Lightwork

[![CI](https://github.com/Daybreak-AI-Labs/LightworkOS/actions/workflows/ci.yml/badge.svg)](https://github.com/Daybreak-AI-Labs/LightworkOS/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.11 | 3.12](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](docs/source-install.md)

Lightwork is a self-hosted runtime for multi-agent AI work. You give it a goal,
and an orchestrator agent plans the work, hands parts of it to specialist
sub-agents running on the models you choose, checks their results and returns
an answer. Inputs, tool calls and answers are screened by a safety layer,
commands run in a configurable sandbox, per-run spending and time limits are
enforced, activity is recorded in a signed audit log, and state persists
between runs in a world-model database.

## Status

Lightwork is alpha software. The eight Python packages on `main` are version
0.1.7 in [`release-cohort.toml`](release-cohort.toml), which is unreleased. No
GitHub release, PyPI package or container image is currently published, so
installing from source is the supported path. Published releases will be
listed on the
[releases page](https://github.com/Daybreak-AI-Labs/LightworkOS/releases).
Configuration and APIs can change between versions; [CHANGELOG.md](CHANGELOG.md)
records notable changes. Supported Python versions are 3.11 and 3.12, the
versions tested in CI.

## Quickstart

Requires Git and Python 3.11 or 3.12.

```bash
git clone https://github.com/Daybreak-AI-Labs/LightworkOS
cd LightworkOS
python3 -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python scripts/install_release_cohort.py --core-extra release-runtime,evidence-analysis
lightwork doctor
lightwork dashboard             # serves the dashboard at http://127.0.0.1:8765
```

`install_release_cohort.py` installs the eight Lightwork packages together, in
one pip transaction, against the pinned constraints in `requirements/ci.txt`
(the repository root is not itself a pip project). `lightwork doctor` checks
the installation and configuration and suggests a fix for anything it flags.
The dashboard at <http://127.0.0.1:8765> guides first-owner sign-in and
provider setup; `lightwork init` runs the setup wizard in the terminal
instead. Windows PowerShell commands and the post-install checks are in
[Install from source](docs/source-install.md).

Once a provider is connected, run a first task from the dashboard's chat or
the terminal. This one needs no file or program access:

```bash
lightwork start "Draft a one-page plan to reduce our customer support response time without adding headcount. State your assumptions and the facts you need from me."
```

> **Where commands run.** Agents can run model-generated shell commands. With
> the `local` sandbox backend, the configuration default, those commands run
> directly on your machine, so a successful prompt injection would be code
> execution on the host. Use a container backend (`docker` or `podman`) for
> any goal you would not run yourself. The quick setup in `lightwork init`
> selects Docker when it is running. Without Docker, and in the dashboard's
> initial settings, file changes and program execution start switched off; to
> turn them on, start Docker or Podman, choose its container under
> **Permissions → Where work runs** in the dashboard, then choose **Allow file
> work**. Read the
> [execution posture](SECURITY.md#execution-posture) before running untrusted
> goals.

The command-line tool is installed under two names, `lightwork` and
`maverick`, which run the same program. Python distributions, modules,
environment variables and the config directory use the original codename
(`maverick-agent`, `MAVERICK_*`, `~/.maverick/`).

## Architecture at a glance

```
  goal  (CLI, dashboard, REST API, MCP, messaging channel)
    │
    ▼
  Shield: input scan ─────────────── block ──▶ refused
    │
    ▼
  Orchestrator agent: plans, delegates, verifies, answers
    │  spawn_subagent / spawn_swarm
    ├──────────────┬──────────────┐
    ▼              ▼              ▼
  researcher     coder          writer     specialist sub-agents, model chosen per role
    │              │              │
    └── tool call ─┴─▶ Shield: tool-call scan ─▶ tools; shell runs in the sandbox
    │
    ▼
  Shield: output scan ─▶ answer

  Shared by every agent in a run:
    World model   SQLite + FTS5, or Postgres: goals, runs, facts, conversations, approvals
    Budget        dollar, wall-clock, token and tool-call caps
    Audit log     append-only NDJSON, hash-chained and Ed25519-signed
```

Lightwork ships as eight Python distributions, installed and versioned
together as one cohort:

| Distribution | Path | What it contains |
|---|---|---|
| `maverick-agent` | [`packages/maverick-core`](packages/maverick-core) | The kernel: orchestrator, tools, sandbox backends, world model, budget, audit log, CLI |
| `maverick-shield` | [`packages/maverick-shield`](packages/maverick-shield) | Agent Shield integration and the built-in rule set |
| `maverick-channels` | [`packages/maverick-channels`](packages/maverick-channels) | Messaging adapters used by `lightwork serve` |
| `maverick-dashboard` | [`packages/maverick-dashboard`](packages/maverick-dashboard) | FastAPI web dashboard and REST API at `/api/v1` |
| `maverick-mcp-server` | [`packages/maverick-mcp`](packages/maverick-mcp) | Model Context Protocol server that exposes Lightwork as a tool |
| `maverick-evolve` | [`packages/maverick-evolve`](packages/maverick-evolve) | Config-only evolutionary search with an evaluation harness |
| `maverick-knowledge` | [`packages/maverick-knowledge`](packages/maverick-knowledge) | Per-domain document knowledge (vector retrieval) |
| `maverick-installer` | [`apps/installer-cli`](apps/installer-cli) | The interactive setup wizard behind `lightwork init` |

[ARCHITECTURE.md](ARCHITECTURE.md) describes the components and how a goal
moves through them; [docs/architecture.md](docs/architecture.md) covers the
runtime primitives in more depth.

## Key capabilities

- **Orchestration with per-role models.** The orchestrator spawns specialist sub-agents (researcher, coder, writer, verifier and others) that work in parallel. Each role's model is set independently as `provider:model-id`; `lightwork version` prints the registered providers: `anthropic`, `openai`, `azure`, `bedrock`, `vertex`, `gemini`, `deepseek`, `xai`, `moonshot`, `openrouter`, `ollama`, `tgi`, `vllm`, `openai_compatible` and `codex_cli`.
- **Agent Shield at three chokepoints.** User input, every tool call and every final answer are scanned, together with decoded variants that unpack base64, hex and percent-encoding and fold look-alike Unicode characters. Profiles range from `strict` to `permissive`. The built-in rule set is what ships; the full agent-shield SDK is not published. See [docs/safety.md](docs/safety.md).
- **Sandboxed execution.** Commands run through a configurable backend: `local`, `docker`, `podman`, `gvisor`, `devcontainer`, `kubernetes`, `ssh` or `modal`. Docker and Podman run each command in a throwaway container with all Linux capabilities dropped, a process limit and, by default, no network. The `firecracker` backend is an experimental scaffold, not a supported isolation backend.
- **Spending and time limits.** A budget tracker enforces dollar, wall-clock, token and tool-call caps each time it records usage, not only at explicit checks, so a run stops at the first call that crosses a cap. The installer offers a $2 and 30-minute task limit by default, which you can change or turn off. See [docs/task-limits.md](docs/task-limits.md).
- **Tamper-evident audit log, with a stated key-custody limit.** Audit events are hash-chained and Ed25519-signed by default, and `lightwork audit verify` exits non-zero on any break; by default the signing key lives on the same host, which catches accidental or unprivileged edits but not an actor running as the service account, so supply the key from outside the host (`MAVERICK_AUDIT_SIGNING_KEY`, or a KMS-wrapped `MAVERICK_AUDIT_SIGNING_KEY_WRAPPED`) and keep audit checkpoints off-host to narrow that gap.
- **Independent audit verification.** [`rust/maverick-verify-audit`](rust/maverick-verify-audit/README.md) is a standalone binary that checks the same chain without Python, `lightwork audit checkpoint` publishes the signed audit tip to an independent location and later verifies the log against it, and `lightwork audit export` writes the log as JSONL or ArcSight CEF for a SIEM. See [docs/audit-checkpoints.md](docs/audit-checkpoints.md).
- **Approvals and capabilities.** A connector change to an external system appears on the dashboard's Approvals page with every request field and a digest of the exact request, and is sent only after a person approves it; the agent cannot approve its own request. Other high- and critical-risk actions require confirmation by default. An agent can stop and ask the person who started a goal a question (`lightwork answer`, `lightwork resume`). With capability enforcement on (`MAVERICK_ENFORCE_CAPABILITIES=1`, or enterprise mode), a spawned sub-agent's grant is attenuated from its parent's and can never exceed it; `lightwork whoami` shows a principal's effective grant, and `lightwork halt` requests a halt at upcoming execution checkpoints.
- **Enterprise mode.** `MAVERICK_ENTERPRISE=1` (or `[enterprise] mode = true`) pins model calls to local or self-hosted providers, refusing a cloud call before any prompt is sent, checks each outbound request made through the supported Python HTTP clients, turns on capability enforcement, and makes every consent-gated action require a person's decision (a headless run is refused). It is an application-layer control, so pair it with sandbox network isolation and a network egress policy; `lightwork airgap` checks the configuration for outbound paths. See [docs/security-hardening.md](docs/security-hardening.md).
- **Keys and data at rest.** Sensitive local stores are encrypted with AES-256-GCM by default ([docs/encryption.md](docs/encryption.md)). An optional out-of-process model proxy (`python -m maverick.model_proxy`, with a Go port in [`go/model-proxy`](go/model-proxy/README.md)) holds provider API keys so they never enter the agent's process.
- **Persistent world model.** Goals, runs, facts, conversations and approvals persist in SQLite with full-text search, or in Postgres, and carry over between runs.
- **Specialist packs.** 2,031 built-in domain packs, each a TOML file that declares a persona, the tools it may and may not use, a maximum risk level, the compartment it is sealed into and a step-by-step workflow. Invariant tests run across the whole roster: no drafting pack can reach a state-mutating tool, a pack still in onboarding never acts autonomously and no high-risk action ever does, a spawned agent never exceeds its parent's grant, a compartment seal never reaches another compartment, and the hard-refusal floor cannot be removed.
- **Connectors and MCP.** A registry of 2,877 write-capable REST and GraphQL connectors, plus dedicated modules for common business systems; each needs its own credentials. The kernel also consumes external MCP servers as tools (`lightwork mcp-registry`). See [docs/connectors.md](docs/connectors.md).
- **Messaging channels.** `lightwork serve` connects agents to Telegram, Discord, Slack, Microsoft Teams, Mattermost, Signal, email, Matrix, Bluesky, Mastodon, Threads, IRC, RCS, WhatsApp (Meta Cloud API or Twilio), SMS (Twilio), iMessage (macOS only) and voice.
- **Workflows.** An optional flow engine runs graphs of agent steps, fixed actions, branches, loops, parallel steps, approvals and delays, with a visual designer in the dashboard. It is off by default (`[flows] enable`).
- **Reviewable learning.** By default Lightwork distills successful runs into proposed skills without widening any agent's permissions; a proposed skill is used in later runs only after a person reviews and admits it on the dashboard's Skills page (`[self_learning]`, `lightwork skills`). Proposed changes to the agents' own prompts, skills and memory (`lightwork refine`, off by default) never apply themselves: each waits for approval and is snapshotted so it can be reverted. Code self-modification (`lightwork self-modify`) is off by default and research-only; it can propose and test a patch but never applies one. See [docs/self-learning.md](docs/self-learning.md).

The catalogue of shipped features is in [docs/FEATURES.md](docs/FEATURES.md).

## CLI essentials

| Command | What it does |
|---|---|
| `lightwork init` | Interactive setup wizard (`--fast` for recommended defaults, `--from-file` for headless provisioning) |
| `lightwork doctor` | Diagnose the installation and configuration, with remediation hints |
| `lightwork preflight` | Offline install-readiness check; exits non-zero on a blocker |
| `lightwork version` | Installed package versions, schema, shield backend and registered providers |
| `lightwork dashboard [--host --port]` | Local web dashboard and REST API (default `127.0.0.1:8765`; a non-loopback host requires `MAVERICK_DASHBOARD_TOKEN` in the server environment) |
| `lightwork start "GOAL" [--max-dollars --max-wall-seconds --sandbox --template]` | Run a goal once |
| `lightwork chat` | Interactive REPL; each turn becomes a goal |
| `lightwork status` / `logs` / `answer` / `resume` | Inspect recent goals, read recent audit entries, answer an agent's question, resume a blocked goal |
| `lightwork schedule goal / add / list / rm` | Schedule recurring goals and jobs with cron expressions |
| `lightwork worker [--once]` | Run the background job worker that executes scheduled jobs |
| `lightwork serve` | Start the channel server for configured messaging channels |
| `lightwork mcp [--http]` | Start the MCP server on stdio, or over Streamable HTTP |
| `lightwork config show / path / edit` | Show, locate or edit `~/.maverick/config.toml` |
| `lightwork safety [--json]` | Print the safety posture: shield, sandbox backend, egress policy |
| `lightwork airgap` | Check the configuration for any outbound path; exits non-zero on a finding |
| `lightwork audit verify / export / checkpoint` | Verify, export and checkpoint the signed audit log |
| `lightwork whoami` / `capability` | Show a principal's effective grant; revoke or restore grants |
| `lightwork spend` / `budget` | Spend by goal and tag; run cost history |
| `lightwork refine` | Propose, apply and revert changes to the agents' prompts, skills and memory; applying needs an approved proposal |
| `lightwork halt` / `unhalt` | Request a halt at upcoming execution checkpoints; clear it again |

`lightwork --help` lists the other commands.

## Use Lightwork from other tools

**Any MCP client.** `lightwork mcp` is the cross-language interface: spawn it,
list its tools and call one. Short client programs:

- TypeScript / JavaScript: [docs/clients/typescript-quickstart.md](docs/clients/typescript-quickstart.md)
- Go: [docs/clients/go-quickstart.md](docs/clients/go-quickstart.md)
- Rust: [docs/clients/rust-quickstart.md](docs/clients/rust-quickstart.md)
- C# / .NET: [docs/clients/csharp-quickstart.md](docs/clients/csharp-quickstart.md)
- Java / JVM: [docs/clients/java-quickstart.md](docs/clients/java-quickstart.md)

**REST.** The dashboard serves a REST API at `/api/v1`, documented in
[docs/api.md](docs/api.md) and browsable at `/docs` on a running dashboard.

**CI.** Run a goal in GitHub Actions under a hard spend cap with the composite
action in `deploy/github-action`. Pin it to a reviewed full commit SHA:

```yaml
- uses: Daybreak-AI-Labs/LightworkOS/deploy/github-action@<reviewed-full-40-character-commit-sha>
  with:
    goal: "Summarize this PR and flag anything risky."
    max-dollars: "0.50"
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

[docs/github-action.md](docs/github-action.md) covers setup and
[deploy/github-action](deploy/github-action/README.md) has the full input and
output reference. A GitLab CI template is in
[deploy/gitlab-ci](deploy/gitlab-ci/README.md).

**Plugins.** Extend Lightwork with Python packages that declare entry points
(see [docs/plugins.md](docs/plugins.md)), or write agent tools in TypeScript
with the SDK in [`sdks/plugin-ts`](sdks/plugin-ts).

## Repository layout

```
packages/        The eight Python distributions (see the table above)
apps/            Setup wizard, desktop shells, editor extensions and companion apps
sdks/            TypeScript plugin SDK, Python REST client, native consent SDK
extensions/      Browser extension, embeddable chat and status widgets, JavaScript perceptual hash
rust/            Native scanning core and a standalone audit-log verifier
go/              Out-of-process model proxy that keeps provider keys out of the agent
deploy/          Docker, Helm, VPS and cloud recipes; GitHub Actions and GitLab CI integrations
docs/            User, operator and contributor documentation
benchmarks/      Long-horizon, governance and evaluation benchmarks with their harness
proof/           Platform-guarantee checks against the shipped pack roster (run_proof.py)
demo/            Runnable example agents (DSAR, GRC, threat hunting, model risk) and their shared support code
examples/        Client and external-agent examples
scripts/         Install, release and CI helper scripts
requirements/    Pinned constraint files used by the install and CI
build/           PyInstaller spec for the single-file binaries
test_support/    Shared test helpers
```

## Documentation

| Topic | Where |
|---|---|
| Install from source | [docs/source-install.md](docs/source-install.md) |
| First run and first task | [docs/getting-started.md](docs/getting-started.md) |
| Configuration reference | [docs/configuration.md](docs/configuration.md), [docs/env-vars.md](docs/env-vars.md) |
| Deployment (desktop, Docker, VPS, Helm) | [docs/deployment.md](docs/deployment.md), [docs/reference-architectures.md](docs/reference-architectures.md), [deploy/helm/README.md](deploy/helm/README.md) |
| Architecture | [ARCHITECTURE.md](ARCHITECTURE.md), [docs/architecture.md](docs/architecture.md) |
| Safety and security hardening | [docs/safety.md](docs/safety.md), [docs/security-hardening.md](docs/security-hardening.md), [SECURITY.md](SECURITY.md) |
| Threat model | [docs/security/threat-model.md](docs/security/threat-model.md) |
| REST API | [docs/api.md](docs/api.md) |
| Connectors and plugins | [docs/connectors.md](docs/connectors.md), [docs/plugins.md](docs/plugins.md) |
| Feature catalogue | [docs/FEATURES.md](docs/FEATURES.md) |
| Interface contracts and the RFC process | [docs/contracts/README.md](docs/contracts/README.md), [docs/rfcs/README.md](docs/rfcs/README.md) |
| Benchmarks | [benchmarks/README.md](benchmarks/README.md) |
| Changes | [CHANGELOG.md](CHANGELOG.md) |

## Contributing

Contributions are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers the
development setup, tests, lint and CI gates, and how changes reach `main`. In
short:

```bash
git clone https://github.com/Daybreak-AI-Labs/LightworkOS
cd LightworkOS
bash .devcontainer/post-create.sh       # editable installs plus dev tools in .venv
. .venv/bin/activate
python -m pytest -q -n auto --dist loadfile
python -m ruff check .
```

`make help` lists shortcuts for these steps (`make dev`, `make test`,
`make lint`).

Pull request titles follow Conventional Commits, and your first pull request
signs the [Contributor License Agreement](CLA.md) with one line in its
description. Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
[GOVERNANCE.md](GOVERNANCE.md) explains how decisions are made,
[MAINTAINERS.md](MAINTAINERS.md) lists the maintainers, and
[RELEASING.md](RELEASING.md) describes how releases are made. For questions and
bug reports, see [SUPPORT.md](SUPPORT.md). Report security vulnerabilities
privately as described in [SECURITY.md](SECURITY.md), not in a public issue.

## License

Lightwork is licensed under the [Apache License 2.0](LICENSE); see also
[NOTICE](NOTICE) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). The
Lightwork name and logo are trademarks and are not covered by the license; see
[TRADEMARK.md](TRADEMARK.md).

Lightwork is developed by Daybreak Labs.
