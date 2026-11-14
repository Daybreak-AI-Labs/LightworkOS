# Changelog

All notable changes to Lightwork are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The setup wizard saves a search backend only when it needs no key or its key
  is present; supply the provider key before selecting a keyed backend.
- Mattermost and Threads allow-lists now use user IDs only, and the dashboard
  rejects Mattermost entries that are not 26-character IDs; replace saved
  usernames with the person's provider ID.
- Agent MCP tokens saved by `trust add` and by attenuated grants are now hashed;
  clients keep using the original bearer token, and existing raw tokens still
  authenticate.
- Dependency support now includes pypdf 7, cyclonedx-bom 8 and websockets 17,
  while simplejson must remain below 4; use the supplied dependency constraints.
- Shield's published held-out base64 evasion detection is now 71.0% (22 of 31),
  measured without a readable plaintext cue; use this corrected result when
  assessing protection.
- An IMAP source now requires a mail-password environment variable and refuses
  the product's own credential variables; update the source's password variable
  before saving it.
- OpenOCD now refuses a workspace containing a `.cfg` or `.tcl` file unless
  flashing is allowed; review those files and the flashing permission before
  running hardware work.
- MongoDB now refuses `mongodb+srv://` while an egress policy is active; use an
  explicitly permitted `mongodb://` endpoint.
- S3 requests now use path-style addressing; ensure any custom S3 endpoint
  supports that addressing style.
- Model-written `@` characters in Mastodon and Mattermost replies are now
  neutralised, including inside code; copy commands with care because those
  replies contain an invisible separator.
- `audit_days` and all other retention periods now require whole numbers and
  reject booleans; replace values such as `true` or fractional days before
  enforcing retention.
- A sidecar per-principal call limit of `0` now refuses calls; set a positive
  limit when that principal should be allowed to call.
- Re-enrolling an external agent now preserves limits that are not supplied
  and refuses changing a lifetime budget to monthly; request any intended
  limit changes explicitly.
- Serial and ROS writes now require approval; allow for an approval step in
  workflows that write to devices.
- Provider spending now uses one deployment-wide ledger, with earlier
  per-tenant ledgers folded in once; review provider caps against total
  deployment spending rather than a single tenant's spending.
- Configured policy gates now refuse work when their configuration cannot be
  read; repair the configuration before retrying blocked work.
- Browser-vault keys are no longer included in backups by default; retain the
  key separately and supply it when restoring existing vault entries.
- `aria_navigate` no longer accepts `focus`; remove that action from callers.
- Signed plugins now refuse extra executable files in their owned package
  directories; rebuild and re-sign packages that ship new code or native files.

### Fixed

- Resuming setup with an invalid saved advanced answer now asks the advanced
  step again, while a config-write error preserves the resume file.
- Sessionless MCP clients can cancel their in-flight requests again without
  affecting clients using distinct session IDs.
- Bluesky polling again looks beyond older indexed pages, and expired login
  tokens can be refreshed without losing the poll.
- Long SMS and WhatsApp replies are split into provider-sized messages, and
  Teams approval cards are shown only to people permitted to see the request.
- Invalid model-supplied task limits no longer increase the host's budget
  ceiling; no configuration change is needed.
- A revocation in `config.toml` now takes precedence over managed trust entries;
  clear that revocation explicitly before restoring access.
- Webhook delivery bodies are now encrypted at rest; run `encryption migrate`
  to cover existing stored bodies.
- Incomplete BigQuery, Snowflake and Databricks statements are now reported as
  unfinished; check their eventual status before treating their output as final.
- Personal-data erasure checks an existing knowledge store even when knowledge
  is disabled; disabling the feature no longer hides that stored data from erase.
- pgvector searches now fall back to an exact search when the index returns too
  few rows, so configured result counts are honoured when enough matches exist.
- Benchmark cases with empty reference answers or no grading criteria no longer count as
  passes, and dry runs are labelled as dry runs; compare scores using the
  corrected evaluation reports.
- Audit verification now detects truncation of the anchor list, and write-once
  audit pushes skip unsigned days without stopping every push.

## [0.1.7] - Unreleased

The initial public release of Lightwork, licensed under the
[Apache License 2.0](LICENSE). It supports Python 3.11 and 3.12. The eight
Python distributions are versioned and released together as one cohort
(`release-cohort.toml`). Versions previously published under the MIT License
remain licensed under it.

### Runtime

- An orchestrator agent plans each goal, delegates parts of it to specialist
  sub-agents (researcher, coder, writer, verifier and others) that work in
  parallel, checks their results and answers. Each role's model is set
  independently as `provider:model-id` across 15 provider backends:
  `anthropic`, `openai`, `azure`, `bedrock`, `vertex`, `gemini`, `deepseek`,
  `xai`, `moonshot`, `openrouter`, `ollama`, `tgi`, `vllm`,
  `openai_compatible` and `codex_cli`.
- A persistent world model in SQLite with FTS5 full-text search, or in
  Postgres, keeps goals, runs, facts, conversations and approvals between runs.
  Released schema migrations are checksum-locked.
- Chat threads: follow-up messages run as goals inside the same conversation,
  so the agent sees the earlier turns.
- An optional flow engine (`[flows] enable`) runs graphs of agent steps, fixed
  actions, branches, loops, parallel steps, approvals and delays, with a
  visual designer in the dashboard.
- A cron scheduler (`lightwork schedule`) and a background worker
  (`lightwork worker`) run recurring goals and jobs; goals can also run out of
  process through a job queue and a shared world model.

### Safety and governance

- Agent Shield screens user input, every tool call and every final answer,
  including decoded variants (base64, hex, percent-encoding and look-alike
  Unicode), with profiles from `strict` to `permissive`. The built-in rule set
  ships with `maverick-shield`, and the kernel runs without the agent-shield
  SDK.
- Commands run through a configurable sandbox backend: `local`, `docker`,
  `podman`, `gvisor`, `devcontainer`, `kubernetes`, `ssh` or `modal`. Docker
  and Podman run each command in a throwaway container with all Linux
  capabilities dropped, a process limit and, by default, no network.
- Budgets cap dollars, wall-clock time, tokens and tool calls, and enforce
  every cap each time usage is recorded.
- The audit log is append-only NDJSON, hash-chained and Ed25519-signed.
  `lightwork audit verify`, `checkpoint` and `export` (JSONL or ArcSight CEF)
  verify, anchor and export it, and `rust/maverick-verify-audit` checks the
  same chain without Python.
- Connector writes to external systems wait for a person's approval on the
  dashboard's Approvals page, and an agent cannot approve its own request.
  With capability enforcement on, each sub-agent's grant is attenuated from
  its parent's; `lightwork whoami` shows a principal's effective grant and
  `lightwork halt` stops work at upcoming execution checkpoints.
- Enterprise mode (`MAVERICK_ENTERPRISE=1`) pins model calls to local or
  self-hosted providers, checks outbound requests made through the supported
  HTTP clients, turns on capability enforcement and requires a person's
  decision for consent-gated actions; `lightwork airgap` checks the
  configuration for outbound paths.
- Sensitive local stores are encrypted at rest with AES-256-GCM, and an
  optional out-of-process model proxy (Python, with a Go port in
  `go/model-proxy`) keeps provider API keys out of the agent's process.

### Interfaces

- The `lightwork` command (also installed as `maverick`), with the setup
  wizard `lightwork init` and the `lightwork doctor` and `lightwork preflight`
  checks.
- A FastAPI web dashboard with a REST API at `/api/v1`, and an in-product
  assistant panel that acts under the same authorization as the direct UI.
- An MCP server (`lightwork mcp`, over stdio or Streamable HTTP) that
  implements protocol `2025-11-25` and negotiates down to `2024-11-05`, with
  client quickstarts for TypeScript, Go, Rust, C# and Java. The kernel also
  uses external MCP servers as tools.
- A2A and gRPC interfaces, and opt-in OpenTelemetry traces and metrics.
- Messaging channels through `lightwork serve`: Telegram, Discord, Slack,
  Microsoft Teams, Mattermost, Signal, email, Matrix, Bluesky, Mastodon,
  Threads, IRC, RCS, WhatsApp, SMS, iMessage (macOS only) and voice.
- A GitHub Action (`deploy/github-action`) and a GitLab CI template, a
  TypeScript plugin SDK (`sdks/plugin-ts`), a Python REST client, editor
  extensions, a browser extension and embeddable widgets.

### Specialists, connectors and learning

- 2,031 built-in domain packs, each declaring a persona, permitted and
  forbidden tools, a maximum risk level, a compartment and a workflow.
  Invariant tests run across the whole roster.
- 2,877 write-capable REST and GraphQL connectors and 37 read-only
  public-data connectors, each using its own credentials.
- Reviewable learning: successful runs are distilled into proposed skills
  that are used only after a person admits them; `lightwork refine` proposes
  prompt, skill and memory changes that apply only once approved and can be
  reverted; code self-modification is off by default and never applies a
  patch.
- `maverick-evolve` runs configuration-only evolutionary search with an
  evaluation harness, and `maverick-knowledge` provides per-domain document
  retrieval.

### Packaging and deployment

- `scripts/install_release_cohort.py` installs the eight distributions in one
  pip transaction against the pinned constraints in `requirements/ci.txt`.
- Recipes for Docker, Helm, a VPS installer and reference architectures (ECS,
  Kubernetes, Fly.io and Railway), and a desktop bootstrap app.
- The release workflow signs its artifacts with Sigstore (cosign, keyless),
  and `deploy/verify-release.sh` verifies a downloaded artifact.
- Signed governance-frontier and harness-overhead benchmark manifests are
  verified in CI against the current sources.

### Known limitations

- Lightwork is alpha software; configuration and APIs can change between
  versions.
- No package is published to PyPI and no container image to a registry yet;
  install from source.
- With the default `local` sandbox backend, model-generated commands run
  directly on the host. Use a container backend for untrusted goals.
- By default the audit signing key lives on the same host, which detects
  unprivileged edits but not changes made by the service account. Supply the
  key from outside the host for stronger tamper evidence.
- The `firecracker` sandbox backend is an experimental scaffold, not a
  supported isolation backend.
- The full agent-shield SDK is not published; the built-in rule set is what
  ships.
- The mobile companion is a preview.
