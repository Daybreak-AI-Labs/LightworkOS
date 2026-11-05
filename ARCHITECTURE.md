# Architecture

Lightwork is a recursive multi-agent swarm with a safety layer at every chokepoint.

## Big picture

```
                          ┌────────────────┐
  user message  ─────────▶│  shield.scan   │──block──▶ reject
                          └───────┬────────┘
                                  │ pass
                                  ▼
                ┌─────────────────────────────────────┐
                │      Orchestrator agent (Opus)      │
                │  plans → spawns → verifies → final  │
                └─────────────────┬───────────────────┘
                                  │ spawn_swarm / spawn_subagent
                     ┌────────────┼────────────┐
                     ▼            ▼            ▼
                 researcher     coder        writer     (parallel Sonnet workers)
                     │            │            │
                     └────────────┴────────────┘
            shared state via SwarmContext:
              • Blackboard (per run, in-memory)
              • WorldModel (SQLite, persistent)
              • Budget (global token/$/wall/tool caps)
              • Sandbox (local / docker / ssh / ...)
              • Shield (input / tool / output scans)

  Models shown are the default role routing; every role is configurable.
```

## Components

### `packages/maverick-core/`

The agent kernel.

| Module | Role |
|---|---|
| `agent.py` | The recursive `Agent`. Every node in the swarm is one of these. |
| `orchestrator.py` | Entry point `run_goal()` — wires SwarmContext, spawns external MCP clients, runs the root agent, distills the trajectory into a skill. |
| `swarm.py` | `SwarmContext` shared by all agents in a run. |
| `blackboard.py` | Append-only shared workspace for one run. Mirrors entries into `world.goal_events` when `attach_world()` is called so the dashboard can stream live progress. |
| `world_model.py` | SQLite: goals, episodes, facts, questions, messages, goal_events. WAL mode + `busy_timeout=5000` for safe concurrent dashboard+agent access. Forward-only, checksum-locked schema migrations (`world_model.MIGRATIONS`). |
| `budget.py` | Hard caps on tokens, $, wall-clock, tool calls. Raises `BudgetExceeded`. |
| `llm.py` | Multi-provider adapter: Anthropic, OpenAI, Azure, Bedrock, Vertex AI, Gemini, xAI, DeepSeek, Moonshot, OpenRouter, Ollama, TGI, vLLM, any OpenAI-compatible endpoint and the Codex CLI (`providers.KNOWN_PROVIDERS`). Per-role model routing via config. |
| `providers/` | One adapter file per provider; OpenAI ↔ Anthropic message translation lives in `openai_provider.py`. |
| `config.py` | TOML config loader. Per-role model choice + persona + MCP server table. |
| `skills.py` | Auto-distill successful trajectories into reusable SKILL.md files. Strict skill source validation: `https://` and `gh:org/repo[:path]`, plus local paths from the CLI only (the REST API rejects bare paths); `http://`, `file://`, `ftp://`, `gopher://`, `data:` and `javascript:` sources are refused. |
| `skill/embeddings.py` | Optional ONNX embeddings via fastembed; falls back to lexical match if unavailable. |
| `persona.py` | `[persona]` config block renders a name/style/addendum into every agent's system prompt. |
| `mcp_client.py` | Spawns external MCP servers as subprocesses, drains their stderr, registers their tools. |
| `runner.py` | `run_goal_in_thread(...)` — process-wide BoundedSemaphore-capped background runner shared by the dashboard, REST API, and MCP server. |
| `health.py` | `maverick doctor` — every red/yellow row carries an actionable `fix=...` remediation. |
| `cli/` | The `maverick` / `lightwork` command tree (`cli/__init__.py` plus `_*_groups.py` modules); `lightwork --help` lists the commands. |
| `sandbox/` | Execution backends: `local.py` (subprocess), `docker.py` (`--network=none` default), gVisor (`runsc` runtime), `podman.py`, `devcontainer.py`, `kubernetes.py`, `firecracker.py`, `ssh.py` (uses user's `ssh` binary + keys), `modal_backend.py` — nine selectable. |
| `tools/` | The built-in tools, including `read_file`, `write_file`, `list_dir`, `shell`, `ask_user`, `spawn_subagent` and `spawn_swarm`. |

### `packages/maverick-shield/`

Thin Python wrapper over `agent-shield`. Provides three chokepoints:

- `Shield.scan_input(text)` — before user input enters the orchestrator
- `Shield.scan_tool_call(name, args)` — before any tool executes
- `Shield.scan_output(text)` — before the final answer reaches the user

If `agent-shield` is not installed, Lightwork falls back to the built-in rule set (43 rules) (`builtin_rules.py`): ignore-previous prompt injection, ChatML/DAN jailbreak, `rm -rf /`, curl-pipe-shell, sensitive file reads, etc. The shield never silently no-ops — `Shield.backend` reports which backend is active.

### `packages/maverick-dashboard/`

FastAPI local web UI + REST API.

- **HTML**: `/`, `/goals`, `/skills`, `/facts`, `/spend`, `/chat`, `/chat/goal/{id}` (live-streaming page that long-polls `/api/goal/{id}/events?since=`).
- **REST**: `/api/v1/goals`, `/api/v1/goals/{id}`, `/api/v1/goals/{id}/events`, `/api/v1/goals/{id}/answer`, `/api/v1/facts`, `/api/v1/skills`, etc. OpenAPI schema at `/openapi.json`, Swagger UI at `/docs`.
- **Auth**: layered. A bearer-token middleware (`MAVERICK_DASHBOARD_TOKEN`, `hmac.compare_digest`) plus an optional OIDC gate (`require_principal`) on every route; `/healthz`, `/openapi.json`, `/docs`, `/redoc` are exempt so monitors + API discovery work unauthenticated. HMAC-signed `/webhook/*`, signed `/share/*` links, and SCIM (`/scim/*`, see *enterprise layers*) carry their own credential and bypass both layers.

### `packages/maverick-mcp/`

Lightwork exposed as an MCP server. Hand-rolled JSON-RPC 2.0 (no SDK dep) over both **stdio** and a **streamable HTTP** transport (`http_transport.py`), negotiating the current protocol version `2025-11-25` with a `2024-11-05` fallback. Core tools (`start_goal`, `goal_status`, `goal_events`, `list_goals`, `answer_question`, `set_fact`, `get_facts`, `list_skills`) plus spec features: async pollable **Tasks** and **elicitation**. The HTTP transport is bearer-gated with a DNS-rebinding (Host/Origin) defense for the loopback case; server-initiated `sampling` is the remaining unimplemented capability. Protocol errors return JSON-RPC `error` payloads (e.g. `-32602`). Run via `maverick mcp`.

### `packages/maverick-channels/`

One adapter per messaging surface, all normalizing to the same `IncomingMessage` shape:

- `telegram`, `discord`, `slack`, `matrix`, `signal`, `email`, `mattermost`, `teams`, `irc`
- `bluesky`, `mastodon`, `threads`, `rcs`, `voice`
- `whatsapp`, `sms` (both via Twilio with **X-Twilio-Signature** verification)
- `whatsapp_cloud` (WhatsApp via the Meta Cloud API)
- `imessage` (macOS; sends via parameterized AppleScript to defeat injection)

This is how phone-companion mode works: the swarm lives on Desktop or VPS, the user talks to it from their phone via Telegram/iMessage/etc.

### `apps/installer-cli/` (`maverick_installer`)

`maverick init` — the interactive wizard, the single source of truth for user-facing UX. Three modes: **consumer** (five questions: name, governance level, key, workdir, budget), **express**, and **advanced**, which walks every capability knob in order (deployment, providers, per-role models, channels, safety, sandbox, budget, learning loops, flows, knowledge, connectors, security suites, plugins, tool ACLs, retention, notifications, A2A, …) followed by API keys, connectors and suites. API keys are stored in `~/.maverick/.env` (mode 0600).

Writes `~/.maverick/config.toml`, then runs a smoke test.

### `apps/installer-desktop/`

Tauri source-bootstrap app (Cargo + tauri.conf.json + Svelte UI): one window that runs the same bootstrap as the command-line installers (`deploy/desktop/install.{ps1,sh}`) behind a progress screen. It is not a self-contained installer; `.github/workflows/desktop.yml` builds it as an unsigned engineering artifact that is not attached to releases.

## Governance, learning & enterprise layers

Beyond the swarm kernel, `maverick-core` carries the subsystems that make
Lightwork a *governed, self-improving* platform rather than a bare runtime. All
are opt-in and additive (kernel rule 1 in `CONTRIBUTING.md` — the kernel runs
unchanged with them off). See `docs/FEATURES.md` for depth.

| Subsystem | Modules | Role |
|---|---|---|
| **Governed Actions** | `governed_actions.py`, `governed_connectors.py`, `governed_rest.py`, `governed_tools.py` | A consequential operation is a typed `ActionSpec`: **simulated** before commit, **gated** on risk/approval (`[actions] require_approval_at`), and **lineage-tracked** (tamper-evident hash chain). `governed_rest` adapts the LIVE enterprise REST connectors into this surface; `governed_tools` always wraps them in the **live tool path** — a connector write is previewed and approval-gated against a standing operator approver (the agent can't self-approve), instead of a bare confirm-gated call. |
| **Closed learning loop** | `dreaming.py`, `hindsight.py`, `reflexion.py`, `self_learning.py`, `skills.py` | Offline consolidation (dream), regression detection (hindsight), snapshot + rollback with a per-cycle signed audit row. |
| **Training flywheel** | `training/ingest.py`, `training/rlaif.py`, `training/reward_model.py` | Verifier rewards → DPO preference pairs (`rlaif`, GPU/torch for the policy update) and a CPU-trainable Bradley-Terry **reward model** (`reward_model`) that learns real weights over structural trajectory features to rank attempts — and, via `rlaif --reward-model`, cross-checks the verifier's preference labels, downweighting DPO pairs the two signals don't corroborate (label-noise mitigation). |
| **Multi-tenancy** | `tenant/registry.py`, `tenant/kms.py`, `paths.py`, `world_model_backends/` | Per-tenant data isolation (`~/.maverick/tenants/<t>/`), per-tenant envelope encryption (DEK wrapped by a KEK), Postgres RLS. |
| **Secrets at rest** | `tenant/kms.py`, `oauth_vault.py` | The OAuth vault seals captured access/refresh tokens under the tenant DEK (no plaintext token files, no cross-tenant readability). |
| **Knowledge / RAG** | `maverick-knowledge/` | Per-domain vector retrieval; embedded `SqliteVectorStore` by default, `PgVectorStore` (pgvector `<=>` cosine + IVFFlat) as the scale-out backend. |
| **Enterprise auth & provisioning** | `oidc.py`, `maverick_dashboard/oidc_login.py`, `maverick_dashboard/scim.py` | OIDC login + a static-bearer SCIM 2.0 `/scim/v2` surface so an IdP (Okta/Azure AD) provisions/deprovisions users → tenants automatically. |
| **Trained-safety seam** | `maverick-shield/probe_model.py` | The Constitutional-v2 cheap probe can ensemble a trained linear classifier (plain-JSON weights, no pickle) by MAX, raising recall without weakening the heuristic floor. |

## Long-horizon properties

What supports long-running work:

1. **Persistent typed world model.** Goals, facts, episodes, and questions survive restarts. The agent can pause overnight and resume.
2. **Recursive spawning with depth + budget caps.** Sub-agents can spawn sub-sub-agents until depth or budget runs out, never longer. Both `spawn_subagent` (blocking) and `spawn_swarm` (parallel) tools.
3. **Closed learning loop.** Beyond per-run skill distillation, the platform runs a full learning lifecycle: `maverick dream` consolidates experience offline (replay → consolidate → rehearse → forget → prune), reflexions and insights are department-scoped, learned state is snapshotted with rollback and a per-cycle audit row, and `maverick hindsight` detects learning regressions by replaying past goals against prior snapshots. External agents can join the same memory plane via fleet memory (MCP). See `docs/FEATURES.md` → *Dreaming*, *Hindsight engine*, *Fleet memory*.
4. **Per-role model routing.** Heavy roles (orchestrator, revisor) get the strongest model; cheap roles (summarizer) get the smallest. Configurable per user.
5. **Async + streaming.** Workers run in parallel via `asyncio.gather`; orchestrator streams output back to user.

## Multi-agent properties

How the agents in one run share state and check each other:

1. **Shared blackboard.** Specialists post observations and findings to a single board the orchestrator reads; they can also message peers directly (`send_to_agent` / `recv_from_agent`), which no pack allowlist removes.
2. **Shared world model.** Facts written by one agent are visible to siblings.
3. **Shared budget.** Tokens, $, tool calls are counted across the entire swarm. One greedy worker can't drain the run.
4. **Shared sandbox.** All workers see the same filesystem and tool state.
5. **Verifier role.** The root agent's `FINAL:` answer is verified (`verifier.verify_final`, or the fail-to-pass tests in coding mode). On rejection the same agent revises once with the critique.

## Deployment targets

| Target | How it runs |
|---|---|
| **Desktop** | Source checkout installed into a virtual environment ([docs/source-install.md](docs/source-install.md)); state lives in `~/.maverick`. |
| **Docker** | Built from `deploy/docker/Dockerfile` (or `deploy/docker/docker-compose.yml`); runs as an unprivileged user with `~/.maverick` mounted at `/home/maverick/.maverick`. |
| **VPS** | `deploy/vps/install.sh` installs the release cohort with pipx and provisions a systemd unit. `MAVERICK_REF`, a full 40-character commit SHA, is required and pins the exact source commit it installs. |
| **Phone (companion)** | Swarm runs on Desktop or VPS; phone talks via Telegram / iMessage / WhatsApp / Signal / Discord / Slack / SMS / Matrix / email. A native mobile companion is in preview in `apps/mobile-companion/`. |

No prebuilt binaries, container images or PyPI packages have been published yet.

## Distribution channels

`.github/workflows/release.yml` runs when a `v*` tag is pushed, and `.github/workflows/publish.yml` runs after it; `RELEASING.md` describes the procedure.

- **GitHub Releases**: PyInstaller single-file binaries for Linux x86_64, macOS arm64 and Windows x86_64, and CycloneDX SBOMs, each **Sigstore-signed keyless** (cosign via GitHub OIDC — `.sig` + `.pem` per artifact, logged to Rekor; verify with `deploy/verify-release.sh`); plus the Python wheels and sdists with their Sigstore bundles.
- **GHCR**: one container image tag per release, `ghcr.io/daybreak-ai-labs/lightworkos:<version>`, promoted from a signed staging digest.
- **PyPI**: the eight distributions in `release-cohort.toml` (`maverick-agent` for the core package, whose import and CLI name remain `maverick`, plus `maverick-shield`, `maverick-channels`, `maverick-evolve`, `maverick-dashboard`, `maverick-mcp-server`, `maverick-knowledge` and `maverick-installer`) through PyPI trusted publishing. Publishing to PyPI is switched off until the repository variable `MAVERICK_PUBLIC_PYPI_ENABLED` is set to `true`.

## Adding a new feature

The rule of thumb (see the house rules in `CONTRIBUTING.md`):

- Capability code goes in a package under `packages/`.
- Entry points / UX go under `apps/`.
- The wizard (`apps/installer-cli/`) must learn to enable/disable it, otherwise non-technical users can't reach it.
- Defaults live in code; user overrides live in `~/.maverick/config.toml`.
