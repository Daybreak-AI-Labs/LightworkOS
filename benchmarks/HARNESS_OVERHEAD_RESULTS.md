# Governance-overhead benchmark — measured results

> **MEASURED:** the governed arm added **no** model calls, tokens, or task steps
> and returned a byte-identical answer and effect in 36/36 paired instances, at a median measured cost of
> **35.33 ms per task** for 6 durable evidence
> artifacts per task.
>
> This is an offline deterministic overhead measurement on one host. It is **not**
> a capability benchmark: no LLM is in the loop, and nothing here speaks to task
> quality, accuracy, or competitive model performance.

## What is measured

12 fixed task definitions across two shapes (`analysis`, `actuation`) are executed twice under seeds [11, 23, 37]:

- **ungoverned** — the task steps run directly: no budget meter, no tool
  authorization, no receipts, no audit rows, no shield screening;
- **governed** — the *same* steps run through the real control plane.

Controls engaged in the governed arm:

- `budget.Budget (token/dollar/wall/tool caps, checked per step)`
- `tool_authz.authorize (tool policy, shield scan, org policy, signed row)`
- `governed_actions.record_tool_lineage (PREPARE/COMMIT receipts)`
- `world_model approvals + safety.dual_control quorum`
- `audit.audit_event run-lifecycle rows on the signed chain`
- `shield_policy.scan_block + memory_guard.injection_markers`
- `safety.secret_detector.redact at the evidence boundary`

The model boundary is `stub://deterministic-sha256-v1`: a pure SHA-256 function of the
prompt. Both arms call it, so any token or call-count difference between the arms
is caused by governance and nothing else.

## Run identity

- Suite: `harness-overhead-v1`
- Started: `2026-11-04T21:12:58.725954+00:00`
- Git commit: `b05c5ff82ec28a3ca1c90209b5b5fe3b73dbd6c6`
- Working tree dirty during run: `false`
- Paired instances: 36 (36 governed, 36 ungoverned)
- Model in loop: `false`; network used: `false`
- Network claim basis: the model boundary is a pure sha256 function of the prompt; no provider client is constructed and no socket is opened; config, tenant/client, deployment profile, and injected or KMS-wrapped audit-key inputs are cleared
- Budget caps enforced per governed task: `{"max_dollars": 1.0, "max_input_tokens": 200000, "max_output_tokens": 50000, "max_tool_calls": 64, "max_wall_seconds": 600.0}`
- Shield: installed `true`, backend `builtin_rules`, required `false`
- Input digest: `357355946ba031cc6a6f336e42ae152e99c431d869632221434d1aad8dbbd8be`
- Manifest signature: `ed25519` (self-signed run integrity)
- Signed manifest file SHA-256 (UTF-8/LF): `4555038fbe341ce01c1e4d63ac1f9192d4c4a833f501980e22122dc86bbade8e`
- Public evidence: [signed measured manifest](./results/harness-overhead-v1/measured-manifest.json) and [trusted publisher key](./results/harness-overhead-v1/trusted-publisher.pub)

## Headline: what governance did not cost

| Quantity | Governed | Ungoverned | Delta | Ratio |
|---|---:|---:|---:|---:|
| Model calls | 36 | 36 | +0 | 1.0000× |
| Input tokens | 3,582 | 3,582 | +0 | 1.0000× |
| Output tokens | 1,722 | 1,722 | +0 | 1.0000× |
| Task steps | 126 | 126 | +0 | 1.0000× |
| Tool calls | 90 | 90 | +0 | 1.0000× |

Answers byte-identical across arms: 36/36 (100.0%). External effects (the posted ledger file) byte-identical: 36/36 (100.0%).

A zero token delta is a property of *this* control plane, not a truism: a
governance layer implemented with an LLM critic or an LLM-as-judge policy would
show a positive delta here. Lightwork's controls are deterministic code, so they
add no model calls.

## Headline: what governance did cost

| Path | Samples | Median | p95 |
|---|---:|---:|---:|
| Ungoverned task | 36 | 684.1 µs | 2.27 ms |
| Governed task | 36 | 36.44 ms | 67.91 ms |
| Paired governance overhead | 36 | 35.33 ms | 65.65 ms |

- Median governed/ungoverned wall ratio: 53.2756×
- Median overhead per durable evidence artifact: 5.89 ms

**Read the ratio carefully.** The ungoverned denominator here is pure local
computation against a stubbed model — microseconds. A large ratio against a
microsecond baseline is arithmetic, not a finding. The defensible number is the
absolute overhead in the table above. As a clearly-labelled projection (an
assumption, not a measurement): if each step of a real task cost 1.0 s of model
latency, the measured per-task overhead would be 0.9994% of wall time.

## Evidence produced in exchange

| Durable artifact | Count | Per task |
|---|---:|---:|
| `approvals` | 18 | 0.50 |
| `lifecycle_audit_rows` | 72 | 2.00 |
| `lineage_receipts` | 36 | 1.00 |
| `native_audit_rows` | 90 | 2.50 |
| **total** | **216** | **6** |

| Control invocation | Count | Per task |
|---|---:|---:|
| `authz_allowed` | 90 | 2.50 |
| `authz_denied` | 0 | 0.00 |
| `budget_checks` | 126 | 3.50 |
| `injection_screens` | 36 | 1.00 |
| `secrets_redacted_in_evidence` | 9 | 0.25 |
| `shield_screens` | 36 | 1.00 |
| **total** | **297** | **8.25** |

### By task shape

| Shape | Instances | Evidence/task | Ungoverned median | Governed median | Overhead median |
|---|---:|---:|---:|---:|---:|
| `actuation` | 18 | 8 | 1.61 ms | 40.72 ms | 39.24 ms |
| `analysis` | 18 | 4 | 48.6 µs | 21.32 ms | 21.28 ms |

The `actuation` shape ends on a high-risk posting action, so it pays for an
approval and a PREPARE/COMMIT receipt pair that the read-only `analysis` shape
never incurs. That split is the shape of the cost: governance overhead tracks the
number of *consequential* actions, not the number of steps.

Durable artifacts are counted from what was *persisted* — receipts are read back
from the lineage store, audit rows from the signed chain, approvals from the
world model. Control invocations gate the run but persist nothing on their own,
so they are reported separately and never inflate the artifact count.

The ungoverned arm produced 0 governance artifacts of any kind.
That is the control on this measurement: if the ungoverned arm were quietly
governed, this number would not be zero.

## Evidence integrity

- Audit rows counted by the harness: 171; rows read back off the signed chain: 171
- Total signed audit events on the chain: 172 (the measured rows plus one chain-initialisation row written before the first task)
- Audit-chain SHA-256: `3aef99dcf5fd48afbf32ef36e1cd48c02d3252ce00f23d979b23bda469fb9ea6`
- Audit chain verified in-run: `true`
- Lineage chains carrying receipts: 18; verified: 18
- Injection tripwires fired by the memory guard: 9
- Secrets redacted before reaching the evidence boundary: 9
- Key custody: ephemeral co-located benchmark key; self-signed run integrity only, not off-host custody or publisher identity.
- Off-host signing key active: `false`

## What this does not show

- **Not a capability benchmark.** No LLM is in the loop. This measures the cost of
  the control plane, not the quality, accuracy, or intelligence of any agent.
- The model boundary is stubbed with a pure function, so nothing here bears on
  provider latency, retry behaviour, streaming, or token accounting under a real
  model. Dollar figures are computed at Lightwork's fallback rate card purely to
  exercise the metering path; they are not a price claim.
- Wall-clock numbers are local-machine observations on one host, one filesystem,
  and one background load. They are recorded but never asserted; `--ci` gates only
  the deterministic facts.
- Twelve task definitions across two shapes are fixed examples of a read-only and
  a consequential pipeline. They are not statistical coverage of enterprise work,
  and a task with a different tool mix will produce a different artifact count.
- Governance overhead scales with the number of *consequential* actions — see the
  by-shape table above. A workload with more high-risk actions pays more, and the
  headline median is a blend of the two shapes measured here, not a constant.
- The audit and approval stores here are a temporary directory on local disk. A
  deployment writing to network storage or Postgres will measure different
  numbers.
- Run-lifecycle audit rows are emitted by this harness through the product's own
  `audit_event` API; the `tool_call` rows are emitted natively inside
  `tool_authz.authorize`. The two are counted separately above rather than
  presented as one number.
- The signature establishes run integrity against accidental edits only. The key
  is co-located and ephemeral: it is not off-host custody and does not establish
  publisher identity.

## Reproduce

```bash
python3 benchmarks/eval_harness_overhead.py --ci
python3 benchmarks/eval_harness_overhead.py
python3 benchmarks/eval_harness_overhead.py --verify-tracked-artifacts
python3 benchmarks/eval_harness_overhead.py --verify-manifest \
  benchmarks/results/harness-overhead-v1/measured-manifest.json \
  --trusted-pubkey-file benchmarks/results/harness-overhead-v1/trusted-publisher.pub
python3 -m pytest -q packages/maverick-core/tests/test_eval_harness_overhead.py
```

`--ci` re-measures and asserts only the deterministic facts: answer and effect
equality, model-call/token/step parity, the exact evidence-artifact counts, that
every authorization was allowed, that the redaction and injection screens fired,
and that the ungoverned arm produced no governance artifacts. Timings are printed
and recorded, never asserted.

## Defensible claim

> Across 12 deterministic task definitions, three pinned order seeds, and matched
> ungoverned baselines, Lightwork's control plane added no model calls, no tokens,
> and no task steps (100% of paired instances
> produced a byte-identical answer and effect), at a median measured cost of
> 35.33 ms per task, while producing 6 durable
> evidence artifacts per task. This measures overhead, not capability.
