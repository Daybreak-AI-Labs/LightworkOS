# Architecture: the governed agent runtime

Lightwork is a **governed agent runtime** — a recursive multi-agent swarm
wrapped in the runtime primitives most agent frameworks skip: hard budgets,
sandboxed execution, signed tamper-evident audit, attenuating capabilities,
and a content shield. The agent loop is the easy part; the governance around it
is the differentiator.

A useful lens for this architecture is the operating system. An OS multiplexes
processes onto hardware under scheduling, isolation, permissions, and resource
limits; Lightwork multiplexes *agents* onto LLMs and tools under the same kinds
of controls. The mapping below makes that lens concrete.

This is a **lens, not a product claim.** Lightwork is not an operating system
and does not claim to be one. The analogy is a way to reason about which
primitives the runtime owns, and nothing more.

## OS primitives → Lightwork

Each row pairs a classic OS primitive with its agent analog and the Lightwork
module(s) that implement it. "In-process" / "opt-in" notes are deliberate; see
the next section for scope.

| OS primitive | Agent analog | Lightwork today (file) |
|---|---|---|
| Kernel / scheduler | dispatch and schedule agents | recursive swarm with shared context, per-call fan-out cap (`MAVERICK_MAX_SWARM_FANOUT`, default 8 at the root, halved at each level below) and a per-goal total-spawn cap (`[swarm] max_total_spawns` / `MAVERICK_MAX_TOTAL_SPAWNS`, default 64) with an optional per-goal model-call bound (`max_concurrent_model_calls`), parallel tool execution, plus a cron-style scheduler over a durable job queue (`swarm.py`, `tools/spawn.py`, `scheduler.py`, `job_queue.py`, `worker.py`) |
| Processes / isolation | agents + execution sandboxing | 9 sandbox backends behind one `build_sandbox()` factory and a uniform `.exec()` interface — local subprocess, Docker, gVisor, Podman, devcontainer, Kubernetes, Firecracker (experimental scaffold), SSH, and Modal cloud (`sandbox/`) |
| Syscalls / drivers | tools, providers, channels | The built-in tool modules (`tools/`), including 2,877 write-capable token-authed REST/GraphQL connectors and 37 read-only primary-source data connectors; 15 LLM provider backends routable per role (`providers/`, `llm.py`), and MCP client over stdio **and** Streamable HTTP (`mcp_client.py`) |
| IPC | inter-agent communication | append-only blackboard, parent↔child spawn handoffs, and a peer message bus — **in-process today** (`blackboard.py`, `tools/spawn.py`, `agent_bus.py`) |
| Memory management | context = RAM, long-term = disk | turn-list compaction (drop/summarize, opt-in digest RAG), a model-curated cross-session memory directory, and per-goal KV memory (`compaction.py`, `tools/memory.py`, `tools/kv_memory.py`) |
| Permissions / capabilities | per-agent access control | tool allow/deny ACLs, per-identity risk ceilings, destructive-action consent gating, plus Ed25519-signable **attenuating** capabilities that can only narrow as they propagate to children (`safety/tool_acl.py`, `safety/tool_risk.py`, `safety/consent.py`, `capability.py`) |
| Filesystem / state | persistent state | persistent world model (SQLite or Postgres) and durable single-agent checkpoints for crash-resume (`world_model.py`, `checkpoint.py`) |
| Package manager | installable units | skills with trusted Ed25519 publisher verification; MCP catalog installation is disabled pending publisher authentication (`skills.py`, `mcp_registry.py`) |
| Budgets / quotas | cost as a managed resource | a hard per-run `Budget.check()` (dollars / wall-clock / tokens / tool calls) plus opt-in per-principal rolling-window quotas for chargeback (`budget.py`, `quotas.py`) |
| Audit / governance | tamper-evident log | append-only NDJSON with an Ed25519 Merkle-chained signature and offline `verify_chain`, plus GDPR Art.17 erasure (`audit/signing.py`, `audit/erase.py`) |
| Observability | tracing / metrics | opt-in OpenTelemetry spans + Prometheus `/metrics`, wrapping kernel turns, tool calls, and provider dispatches (`observability.py`) |
| Identity | users / agents as principals | OIDC ID-token verification mapping an SSO user to a `user:<sub>` principal that drops into the capability + tenant model; agents carry their own signed capability principals (`oidc.py`, `capability.py`) |

The cryptographic substrate is shared on purpose: the same Ed25519 primitives
sign the audit chain, signed skills, and capability grants, so per-agent
identity is a *reuse* of existing crypto rather than a from-scratch build.

## The agent factory: how a specialist comes to exist

Most rows above describe how an *existing* agent runs under governance. A
specialist also has to be *created*, and that path is a pipeline of its own —
one that produces both the agent and the skills/tools its workflow needs, with
the same clamp-then-approve discipline applied at birth rather than mid-run.

A new pack enters through one of two front doors and converges on a single
spine:

1. **Describe** — conversational intake interviews the operator and proposes a
   draft (`run_intake`); or
2. **Demonstrate** — `maverick learn-demo <file>` consumes a reviewed record of
   a person doing the job and induces a draft from that transcript (`demonstration.py`:
   `parse_demonstration` ingests JSONL or prefixed text, secret-redacted and
   input-bounded at the door; `induce_profile` reuses the intake pipeline
   wholesale).

Both front doors then run the **same** spine: `generate_profile` →
`validate_profile` (the envelope **clamp** + persona shield-scan — a
demonstrated pack inherits the identical least-privilege envelope as a described
one) → **human approval** (`save_profile`'s gate) → **provision** (`provision.py`:
`analyze_profile` diffs the draft's workflow and declared `allow_tools` against
installed skills and the live tool registry — `tools.base_tool_names()` — and
surfaces the gaps at the approval gate; `apply_plan` then installs matching
catalog skills via `self_learning.acquire_skill` and synthesizes missing
declared tools via `self_learning.write_generated_tool`) → `agent_from_profile`
spawns the specialist. Provisioning is consent-gated, off by default
(`[self_learning] enable` + `provision_packs`), and **never widens the pack's
already-clamped envelope** — it only fills capabilities the approved workflow
already declares.

Closing the loop, **`factory_learning.py`** feeds *generation quality* back into
the front of the pipeline: provisioning/approval gaps are attributed to a pack's
suite, mined into proposer **corrections**, and promoted through the existing
`SelfImprovementController` on the `prompt` rung (guidance text widens no
capability, so the evidence + calibration gates apply but no escalation proof or
human sign-off is needed). Promoted guidance folds into future pack generation
(`augment_system_prompt`, scope-matched per suite). It is on by default: it
rides the `[self_improvement] enable` switch, and its `factory_learning`
sub-toggle also defaults to on. Set either to `false`, or
`MAVERICK_FACTORY_LEARNING=0`, to keep the generator static. Like provisioning,
it never widens any pack's envelope.

## What's strong, what's deliberately scoped

**Strong.** The primitives a canonical academic agent kernel leaves unowned are
exactly where Lightwork is built out: a hard per-run budget the loop refuses to
exceed (`budget.py`), nine execution sandboxes (`sandbox/`; the Firecracker backend is an experimental scaffold), tamper-evident
signed audit (`audit/signing.py`), and least-privilege attenuating capabilities
(`capability.py`). Tenancy is namespaced on disk by a context-scoped `tenant_id`
(`paths.py`), and content safety runs at three chokepoints via the shield (see
[safety.md](safety.md)).

**Deliberately scoped:**

- **IPC is in-process.** The blackboard, spawn handoffs, and the peer message
  bus are per-process, in-memory structures (`agent_bus.py` is explicit about
  this). Agents coordinate within a single runtime; there is no cross-host
  inter-agent message fabric.
- **Cross-process service supervision is not implemented.** The durable job
  queue and worker (`job_queue.py`, `worker.py`) run scheduled and background
  goals across process restarts, but Lightwork is not a long-lived
  supervisor of independent agent *services* (no per-agent process lifecycle,
  health-checked restart, or placement). The kernel runs a swarm per goal.
- **Durable checkpointing is single-agent.** Crash-resume covers a linear,
  non-spawning agent's loop state; resuming a full spawn tree is not supported
  (`checkpoint.py`).
- **Tenancy is partial.** The cross-session memory store and audit signing keys
  are tenant-scoped; the rest of the world model does not use the same
  partition (`paths.py`).
- **Several governance primitives are opt-in and default-open.** Capability
  enforcement, per-principal quotas, OIDC, and OpenTelemetry are all off unless
  configured, so a single-user install runs without them. Enterprise
  mode flips the relevant defaults to fail-closed (see [safety.md](safety.md)).

In summary: Lightwork's runtime primitives are strongest on budgets,
sandboxing, signed audit, and capabilities; inter-agent IPC stays in-process,
and cross-process service supervision is not implemented.
