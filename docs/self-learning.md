# Self-learning

> **Scope note:** this page covers *capability acquisition* (installing
> skills/tools on demand). The broader learning system — experience
> consolidation (`maverick dream`), department memory, hindsight
> regression detection, learning snapshots/rollback, and the fleet memory
> plane — is catalogued in [`FEATURES.md`](./FEATURES.md) under
> *Dreaming*, *Hindsight engine*, and *Fleet memory*.

When you ask Lightwork to do something it doesn't yet have the capability
for, it can **acquire the capability itself** — install a skill, drive a
REST API, or generate a brand-new tool — instead of giving up. It can also
*propose* a curated MCP server, but only one from the hash-pinned catalog and
only after you explicitly approve it (see "MCP-server acquisition" below).

Governed self-learning is **on by default**: catalog-skill preflight, pack
provisioning, and local skill distillation can learn without broadening an
agent's existing capability envelope. Generating and executing a new tool and
starting a third-party MCP server remain separate, off-by-default trust
decisions.

The DGM code-evolution harness is also separate. `[self_modify] enable` remains
off by default and is never changed by the blanket learning control. A global
client admin can arm it from the dashboard Learning page or
`POST /api/v1/learning/dgm` only after acknowledging its research-only posture.
The enabling payload is `{"enabled": true, "acknowledge_research_only": true}`.
Arming changes the gate; it does not start a cycle or authorize live code
adoption. See [Configuration](configuration.md#learning--workforce-sections) for
its readiness requirements. A valid `MAVERICK_SELF_MODIFY=0|1` environment
override owns the setting and makes the dashboard control read-only.

## Controlling it

The installer enables governed self-learning by default. To make the posture
explicit, edit `~/.maverick/config.toml`:

```toml
[self_learning]
enable           = true  # master switch (default true; set false to opt out)
preflight        = true  # pre-acquire likely skills before each run
create_tools     = false # separate opt-in: generate + run new executable tools
allow_mcp_acquisition = false  # legacy setting; catalog acquisition is unavailable
allow_provider_egress = false  # extra task/result-bearing learning model calls
distill_local    = true  # distill successful local trajectories into skills
max_acquisitions = 5     # cap on auto-acquisitions per run
```

> MCP catalog acquisition is unavailable until publisher authentication is implemented. The legacy `allow_mcp_acquisition` setting and environment override do not enable it.

With `allow_provider_egress = false`, preflight still performs a local,
secret-redacted catalog match and never calls a model. Enabling the egress knob
permits the richer summarizer needs analysis, task-skill synthesis, and
counterfactual credit verification; their inputs are redacted before the call.

The environment variable wins over config: use
`MAVERICK_SELF_LEARNING=0 maverick start "..."` for a one-off opt-out, or `=1`
to force it on when policy permits.

## How it works

There are two triggers, and they share one acquisition engine.

**1. Pre-flight (before the run).** When `preflight` is on, the
orchestrator makes one cheap LLM call to identify specialised
capabilities the goal may need, searches the federated
[catalog](plugins.md) for matching **skills**, and installs the best
hash-verified match. Those steps are already in context on the agent's
first turn.

**2. In-loop `learn_capability` tool (during the run).** When the agent
realises mid-task that it's missing something, it calls this tool:

| op | what it does |
| --- | --- |
| `search` | find catalog skills / MCP servers / plugins matching a need, plus already-loaded tools |
| `acquire_skill` | install a catalog skill by name (hash-verified) and inject its steps immediately |
| `add_mcp_server` | unavailable until MCP catalog publisher authentication is implemented. |
| `create_tool` | generate a Python tool from a description, validate it, and register it live |
| `find_api` | discover an API's OpenAPI spec (probe a `base_url` or web-search), list its operations, and drive it via the built-in `openapi_runner` (no new code) |

Anything acquired is registered into the **live** tool registry, so the
agent can use it on its very next turn — no restart.

**3. At pack birth (the agent factory).** The same acquisition engine also
runs *ahead* of any run, when a new specialist pack is created. Instead of an
agent discovering a capability hole mid-task, the
**agent factory** closes it at creation time:
`provision.analyze_profile` diffs a draft pack's workflow and declared
`allow_tools` against the installed skills and the live tool registry
(`tools.base_tool_names()`), surfaces the gaps at the approval gate, and on
approval `provision.apply_plan` reuses the **same governed paths** —
`self_learning.acquire_skill` for catalog skills (hash-pinned) and
`self_learning.write_generated_tool` for the missing declared tools
(stdlib-only, import-validated out-of-host, consent-gated). Wired into
`maverick onboard` and the `maverick learn-demo` (programming-by-demonstration)
flow. Provisioning **never widens** the pack's already-clamped envelope: it
only satisfies tools already inside `allow_tools` and installs skills (which
carry no tool grant of their own). It's gated by the same `[self_learning]
enable` switch plus a `provision_packs` sub-knob (default on once self-learning
is accepted) and the same human approval `save_profile` requires.

## What persists

- **Skills** install to `~/.maverick/skills/*.md` (the normal skill store).
- **MCP servers** must be independently reviewed and configured by an operator; catalog acquisition is unavailable.
- **Generated tools** are written to `~/.maverick/generated_tools/*.py`.
  When self-learning is enabled, the kernel loads them as first-class
  tools at the start of every run.
- A ledger of everything learned is appended to
  `~/.maverick/learned.ndjson`. List it with:

  ```bash
  maverick learned
  ```

## Safety

Self-learning honors the same chokepoints as the rest of the kernel:

- **Default-on but independently stoppable** — set `[self_learning] enable =
  false`, `MAVERICK_SELF_LEARNING=0`, or the global learning HALT before a run
  to stop this loop. An invalid active config source fails closed.
- **Budget** — any explicitly authorized auxiliary/generation LLM call is metered against the run's
  [budget](configuration.md); `max_acquisitions` bounds churn per run.
- **Static audit (enforced, not just requested)** — generated tool source is
  parsed and checked against a stdlib-only allowlist *before* it is imported:
  disallowed imports (`os`, `subprocess`, `socket`, …), banned builtins
  (`eval`/`exec`/`open`/`__import__`), and the dunder sandbox-escape chain are
  rejected. The `TOOL_AUTHOR_SYSTEM` prompt *asks* for stdlib-only; this layer
  *enforces* it. The source is re-audited every time a persisted tool is
  loaded, so on-disk tampering is caught too. This is a guardrail, not a true
  sandbox (a determined adversary with `getattr` tricks could still evade an
  AST allowlist).
- **Out-of-host import validation** — the check that a generated module
  imports cleanly and exposes a valid `make_tool()` runs in a **short-lived
  child process** (a `sandbox.exec()` child when the call site has a backend,
  otherwise a timed plain subprocess), never the kernel interpreter. So an
  import-time side-effect — or anything the static audit missed — can't touch
  the live process at validation time.
- **Consent gate at first registration** — before a newly generated tool is
  persisted or registered, it goes through the same consent queue as other
  risky actions (`require_consent`, action `register-generated-tool`). Denied,
  auto-deny, or a non-interactive context under a gating consent mode →
  **not persisted, not registered**. Reloads of an already-approved tool do
  **not** re-prompt.
- **Shield** — generated tool source is also scanned through the
  [Shield](safety.md) (when installed) before it is ever imported;
  blocked source is rejected.
- **Catalog trust** — `acquire_skill` only installs curated,
  SHA-256-pinned catalog entries, so a fetched skill must match the
  index byte-for-byte.
- **MCP subprocess safety** — catalog acquisition is disabled; independently configured servers still require review and an appropriate isolation boundary.

### Trust model for generated tools

A generated tool is, in order: **AST-constrained** to stdlib-only,
**import-validated out-of-host** in a child process, and **consent-gated at
first registration**. After it is approved and persisted, its `fn` runs
**in-process at runtime** under the explicit `create_tools` opt-in — the AST
gate and out-of-host check bound *validation*, but execution of an approved
tool still happens in the kernel process. That residual in-process trust is
deliberate and documented; an **out-of-process tool runtime** (running each
generated tool's `fn` in its own sandbox on every call) is the planned future
hardening and is intentionally out of scope here.

Because of that, enabling `create_tools` is a genuine trust decision. Leave it
off (or set `create_tools = false`) if you only want the safer acquisition
paths (skills / APIs). For untrusted goals, also run with a real `[sandbox]`
backend (docker/podman): the out-of-host import check is then a true sandbox,
not just process isolation.

## Self-improving factory

Pack-birth provisioning produces a signal nothing else captures: which
capabilities the factory's drafts keep *missing* — a tool a finance pack kept
declaring but the factory kept omitting, a skill a workflow kept needing, an
envelope a human kept having to widen at approval. `factory_learning.py` closes
that loop back onto *generation quality* instead of letting it die in a log.

Provisioning/approval gaps are attributed to the pack's suite and signal, mined
into proposer **corrections**, and each is promoted through the **existing
`SelfImprovementController`** — on the `prompt` rung, since the correction is
guidance text that widens no capability (so it needs only the evidence and
calibration gates, not the escalation proof / human sign-off a capability
change would). A promoted correction is folded into future pack generation via
`augment_system_prompt`, scope-matched per suite, so the next pack the factory
writes already knows the pattern the last several taught it.

It is **on by default** with governed self-improvement, but remains
independently stoppable with `[self_improvement] factory_learning = false` or
`MAVERICK_FACTORY_LEARNING=0`. While off, recording writes nothing, mining reads
nothing, and `augment_system_prompt` returns the base prompt unchanged. The
ledger is bounded
(oldest rows roll off), outcome text is secret-redacted before it's persisted,
and — like provisioning — a correction is never a tool grant, so it widens no
pack's envelope. Mine and preview the corrections without applying them:

```bash
maverick factory-learn --dry-run
```

Live promotion additionally requires `--evidence` in strict version 2 format:
unique paired held-out case IDs and normalized baseline/candidate scores, frozen
dataset/split/evaluator/model/prompt SHA-256 identifiers, run provenance, and a
canonical payload digest. The gate uses a family-wise-corrected, one-sided
paired empirical-Bernstein lower confidence bound rather than raw mean lift.
Version 1 evidence can still be inspected, but cannot alter the live correction
artifact. Accepted changes use the shared configured improvement margin and a
durable PREPARE → exact-digest CAS apply → COMMIT transaction; evidence lineage
is embedded in the hash-chained promotion receipt.

## Sealed self-harness evaluation boundary

Risk-limited self-harness final queries use a two-phase ledger protocol. Before
any final case is scored, one SQLite `BEGIN IMMEDIATE` transaction reserves the
query, alpha, final-set identity, and declared provider-call, input-token,
output-token, dollar, and compute envelope. The receipt is finalized only after
scoring. A promotion gate first requires that finalization to complete through
`ResearchContainerCandidate`, which invokes `ResearchContainerRunner`; a later
query likewise completes the prior scored query before it can reserve another.
Container or accounting failure keeps the candidate from promotion.
Token and dollar retirement values come from the shared cycle `Budget`; compute
uses elapsed wall time plus container runtime. Because the provider adapter does
not expose a durable request counter, the provider-call axis is charged at the
deterministic scorer-protocol upper bound and labeled by the declared/actual
receipt fields rather than silently releasing possibly consumed capacity.

Submitted Python evaluator candidates run as Linux uid/gid 65532 with a
read-only root, one read-only candidate snapshot, bounded private scratch,
network mode `none`, all capabilities dropped, no-new-privileges, and a fixed
credential-free environment. The runner never falls back to host execution and
never pulls an image. Set `MAVERICK_SELF_HARNESS_EVALUATOR_IMAGE` to a reviewed
image already present in the local Linux Docker engine; the default request is
`python:3.12-slim`, and the resolved immutable image ID is bound into execution
evidence. Opt-in hostile-code acceptance uses
`LIGHTWORK_RUN_RESEARCH_CONTAINER_TESTS=1` and
`LIGHTWORK_RESEARCH_TEST_IMAGE=<local-image>`.

This is a local development custody boundary. On Windows, a verified regular
ledger path and Docker Desktop containment do not prove restrictive ACLs or an
independent evaluator identity: the controller account can still administer the
ledger, evaluator process, and Docker daemon. Set
`MAVERICK_SELF_HARNESS_REQUIRE_INDEPENDENT_CUSTODY=1` for confirmatory use; the
local implementation deliberately fails closed because no separately operated
custodian is installed. Production qualification therefore requires an
external final-set/evaluator custodian and its own operational evidence.

## Evaluator co-evolution

The verifier-calibration interlock (above) keeps learning honest by **freezing**
when the judge stops discriminating. That is the conservative half. The other
half — after *The Red Queen Gödel Machine: Co-Evolving Agents and Their
Evaluators* (arXiv 2606.26294) — is that a *fixed* evaluator eventually stops
giving an informative signal even when it isn't broken: agents saturate it and
the search plateaus. `evaluator_evolution.py` turns freeze-on-drift into
**promote-on-drift**.

A challenger evaluator replaces the incumbent only when its **agreement with a
fixed ground-truth anchor** — measured by the conservative eps-best-belief lower
bound (the eps-quantile of a `Beta(1+S,1+F)` posterior, the same statistic the
paper uses) — beats it. The swap is routed through the **same
`SelfImprovementController`** on a dedicated `evaluator` rung, so it inherits the
evidence floor, the calibration freeze, reversibility, human approval, and the
signed audit. An evaluator only *scores*, so it carries no capability-escalation
surface; but because a swap re-ranks everything it judged, the rung sits above
the default `max_auto_rung` (so a swap needs human approval until an operator
raises the ceiling to `evaluator`). Each promotion advances the slot's **epoch**
and applies **selective erasure** — only the displaced judge's learning records
are discarded, keeping the within-epoch signal stationary.

**The anchor is the guardrail, so the anchor is governed.** A weak, mutable, or
poisoned anchor would launder drift, so released anchors are *immutable*:
checksum-pinned in `evaluator_anchors.lock.json` and enforced by `python -m
maverick.evaluator_evolution --ci` (regenerate after an intentional anchor
addition with `--regen`), exactly as released world-model migrations are.

On by default with governed self-improvement and a no-op when explicitly
paused: it runs only under `[self_improvement] enable` **and** the
`evaluator_evolution` sub-knob.

## MCP-server acquisition

Catalog-sourced MCP server acquisition and hot-start are unavailable until the
publisher and full server configuration can be authenticated. An executable hash
alone does not authenticate its arguments or additional workloads. The legacy
`allow_mcp_acquisition` setting and `MAVERICK_ALLOW_MCP_ACQUISITION` override do
not enable this path. Operators can independently review and configure servers
under `[mcp_servers.<name>]`. Review any servers previously added from a catalog.
