# Lightwork benchmarks

These benchmarks measure long-horizon work, multi-agent coordination, learning
and governance.

## Benchmark design

Each long-horizon benchmark in this directory:

- Has a verifiable success criterion (file produced, tests pass, etc.)
- Records wall-clock, cost (`$`), tokens, tool calls, and depth.
- Is reproducible from a single `maverick start` command.
- Can be compared with a single-shot LLM baseline row.

Results go in [`RESULTS.md`](RESULTS.md), with the run metadata (date, tag,
total cost) checked in.

## How to run a benchmark

```bash
# Pre-req: maverick init has been run with at least an Anthropic key.
maverick start "$(cat benchmarks/longhorizon/research-report.md)" \
  --max-dollars 5 --max-wall-seconds 1800 --workdir bench-workspace
```

When done, copy the output (and the budget summary line) into `RESULTS.md`.
`benchmarks/harness.py` runs the same goal and appends the row for you:

```bash
python benchmarks/harness.py benchmarks/longhorizon/research-report.md \
  --max-dollars 2.0 --tag local
```

## Offline runtime measurements

The opt-in `Runtime performance evidence` GitHub Actions workflow produces a
JSON artifact with median and p95 measurements for a cold process import,
registry assembly, an in-memory SQLite vector search, Unicode normalization,
and an idle event-loop yield. It makes no provider calls and applies no timing
thresholds. To run the same workloads locally with the core and knowledge
packages installed:

```bash
python -m benchmarks.runtime_performance --samples 20 --output runtime-performance.json
```

The vectors are synthetic and the event-loop sample is idle, so the results do
not predict production workload latency. Compare results only when host,
interpreter, dependencies and configuration are equivalent; keep raw artifacts
for review rather than treating machine-dependent timings as pass/fail gates.

## Suite

| Benchmark | Class | Expected wall | Expected cost |
|---|---|---|---|
| `longhorizon/research-report.md` | Research synthesis | 10–20 min | $0.50–$2 |
| `longhorizon/code-refactor.md` | Multi-file refactor | 15–30 min | $1–$3 |
| `longhorizon/multi-step-planning.md` | Planning + revision loop | 20–40 min | $1–$4 |

All three are designed to **fail** for single-shot prompting (too
broad, too many steps) and **succeed** for a recursive swarm with
verify + skill distill enabled.

## Does recall pick the right memory?

Unlike a stateless assistant, Lightwork *retains and recalls* what it learns.
`recall_precision.py` makes the recall side of that claim falsifiable: does
relevance-gating cut injected noise without losing the right skill? It is
deterministic (lexical path), needs no key and runs in CI. It shows the
relevance gate drops the lexical false-positive rate from **50% → 0%** with
Recall@1 held at 100%. Precision is what matters, because injecting
weakly-relevant memory *regresses* the agent (hard negatives flip answers;
large or noisy memory degrades).

## Does the governance contain unsafe autonomy? (the control plane)

Unlike an ungoverned runtime, Lightwork **contains** what an autonomous agent
is allowed to *do*. `eval_governance.py` makes that falsifiable -- and, like
`eval_smoke.py`, it runs in CI with
**no key**: deterministic, scripted calls into the *real* governance machinery.

| Scenario | Asks | Real control exercised |
|---|---|---|
| `approval-gate` | Is a high-risk actuation ("Pay") gated to a human, while a read isn't? | `safety/action_gate` |
| `egress-lock` | Does enterprise mode refuse a cloud LLM provider and admit a self-hosted one? | `enterprise` |
| `capability-ceiling` | Does an attenuating capability deny an out-of-grant tool but permit a granted one? | `capability` |
| `agent-trust` | Is an inbound-only external agent refused an outbound dial? | `agent_trust` |
| `signed-evidence` | Is a governed action recorded on a chain that verifies clean -- and a one-byte tamper detected? | `audit` (Ed25519 chain) |

It reports a **prevention rate** (unsafe vectors contained) *and* a **utility
rate** (legitimate paths preserved), so it can't be gamed by a control that
blocks everything. The broader governed-vs-baseline frontier is implemented by
`eval_governance_frontier.py`. Run the fast wiring smoke standalone:
`python benchmarks/eval_governance.py`.

### Deterministic governance frontier

`eval_governance_frontier.py` expands the smoke to **40 fixed definitions**
(24 unsafe, 16 benign lookalikes) across financial/destructive actuation,
enterprise egress, capability attenuation, agent trust, secret-output policy,
budget controls, and signed-evidence integrity. Every definition runs through:

- the real governed control path; and
- an explicit controls-disabled baseline.

Pinned seeds `17,29,43` change execution order to expose state/order leakage;
they are not model-sampling seeds. The suite separately reports unsafe
prevention, harness decision-ledger coverage, native product-event observation
for supported controls, benign scripted-task completion, false positives,
evidence integrity, and median/p95 measured overhead. Action controls exercise
the production risk-aware secure default: high-risk mutations are denied in a
non-interactive run while benign click/type/fill mutations remain admissible.
It writes an Ed25519-signed reproducibility manifest, emits the run public key
as a separate file, and generates
[`GOVERNANCE_FRONTIER_RESULTS.md`](./GOVERNANCE_FRONTIER_RESULTS.md) from that
verified manifest.

```bash
python benchmarks/eval_governance_frontier.py
python benchmarks/eval_governance_frontier.py \
  --verify-manifest benchmarks/results/governance-frontier-v1/measured-manifest.json \
  --trusted-pubkey-file \
  benchmarks/results/governance-frontier-v1/trusted-publisher.pub
python benchmarks/eval_governance_frontier.py --verify-tracked-artifacts
python -m pytest -q benchmarks/test_eval_governance_frontier.py \
  benchmarks/test_governance_metrics.py
```

No model, provider key, or network is used. “Task completion” here means the
benign scripted terminal action remained admissible; the suite does not measure
natural-language agent completion. Likewise, “prevented”
means the called control returned a denial before the harness marked its
simulated terminal effect admitted; the suite executes no live payment,
deletion, or external side effect. The tracked run uses an ephemeral co-located
signing key and says so explicitly: its signature
proves self-signed run integrity when checked against the separately distributed
public-key file, not off-host production key custody or publisher identity.
The manifest-embedded key is never accepted as its own trust anchor. Publication
validation also checks current harness, control-implementation, and config
digests; a clean measured commit that is an ancestor of `HEAD` when history
preserves it, or the exact signed control-source snapshot after a shallow
checkout, squash, or rebase; and exact deterministic report regeneration.
The control snapshot covers every tracked Python file under `maverick` and
`maverick_shield` plus their package/root metadata, so a change anywhere in that
measured source scope requires regenerating the published artifact. Source
content is decoded as strict UTF-8 and line endings are normalized to LF before
hashing, so Windows CRLF and Linux LF checkouts of identical Git text share the
same signed snapshot; any other content change still invalidates it.

## What does the governance cost? (the overhead)

`eval_harness_overhead.py` answers the objection the frontier suite invites:
if every consequential action carries a receipt, an approval and an audit row,
what does the record *cost*? It runs **12 fixed task definitions** across two
shapes (`analysis`, read-only; `actuation`, ending on a high-risk posting
action) twice under pinned order seeds `11,23,37` — 36 paired instances — with
each task executed both ways:

- **ungoverned** — the step list runs directly: no budget meter, no
  authorization, no receipts, no audit rows, no screening;
- **governed** — the *identical* step list runs through the real control plane
  (`budget.Budget`, `tool_authz.authorize`, `governed_actions` PREPARE/COMMIT
  receipts, world-model approvals at the `dual_control` quorum, `audit_event`
  rows, `shield_policy` + `memory_guard` screens, `secret_detector` redaction).

The model boundary is `stub://deterministic-sha256-v1`, a pure function of the
prompt called by **both** arms, so any token or call-count difference is caused
by governance and nothing else. No key, no network, no LLM: this is an overhead
measurement, not a capability benchmark.

The main result is a **zero** delta: same model calls, same input/output tokens,
same task steps and tool calls, and byte-identical answers and external effects
in every pair. That is a property of *this* control plane, not a truism — a
governance layer built on an LLM critic or an LLM-as-judge policy would show a
positive token delta here. What governance does cost is wall time, reported
against the durable evidence it produces: receipts read back from the lineage
store, audit rows off the signed chain, approvals out of the world model,
counted separately from control invocations that gate a run but persist
nothing. Overhead tracks the number of *consequential* actions rather than
steps, so the `actuation` shape pays visibly more than read-only `analysis`.
The ungoverned arm produced zero governance artifacts of any kind, which is the
control on the measurement. Timings are host-local observations, recorded but
never asserted: `--ci` gates only the deterministic invariants (arm equality,
call/token/step parity, exact artifact counts). Numbers, by-shape split, and
the "what this does not show" caveats live in
[`HARNESS_OVERHEAD_RESULTS.md`](./HARNESS_OVERHEAD_RESULTS.md), generated from
an Ed25519-signed manifest with the run public key emitted alongside it.

```bash
python benchmarks/eval_harness_overhead.py
python benchmarks/eval_harness_overhead.py --ci
python benchmarks/eval_harness_overhead.py \
  --verify-manifest benchmarks/results/harness-overhead-v1/measured-manifest.json \
  --trusted-pubkey-file \
  benchmarks/results/harness-overhead-v1/trusted-publisher.pub
python benchmarks/eval_harness_overhead.py --verify-tracked-artifacts
python -m pytest -q packages/maverick-core/tests/test_eval_harness_overhead.py
```

The three runtime planes that ride these same evidence surfaces — the governed
session kernel, harness self-refinement, and run forking — are documented in
[`../docs/governed-execution.md`](../docs/governed-execution.md).

## Comparing across providers

Re-run the same benchmark with a different `[models]` block in your
configuration (for example, an Anthropic orchestrator with local Ollama
workers) and record each configuration as its own row in `RESULTS.md`, so the
numbers sit side by side.

## Out of scope

- Raw LLM accuracy (MMLU etc.) -- that measures the model, not the agent
  system. No SWE-bench result is published in this directory.
- Raw red-team / prompt-injection content scanning -- that is Agent Shield's
  territory and has its own suite ([`security/README.md`](security/README.md)).
  The *action-governance* layer -- block/gate/record unsafe actions -- **is**
  measured; see "Does the governance contain unsafe autonomy?" above.
