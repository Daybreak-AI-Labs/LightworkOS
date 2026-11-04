# Shield benchmark & safety architecture

This page is written to be **scrutinized**. It reports reproducible, measured
numbers for Lightwork's safety detection — including where it is weak — and
explains why agent safety here is an *architecture*, not a single classifier.
Every number below is produced by `benchmarks/security/detector_score.py`
(offline, no SDK, no API key) and can be regenerated in seconds.

## Defense in depth, not one detector

A prompt-injection classifier alone is a brittle defense: novel phrasings evade
any fixed ruleset, and a single miss can be catastrophic if the agent acts on
it. Lightwork layers detection *and* containment so a miss at one layer is
caught at the next:

1. **Built-in fallback** (`maverick_shield.builtin_rules`) — always present,
   even when the full SDK isn't installed (per the kernel rule "runs without
   the shield, fail-open"). Fast, ReDoS-gated regex + de-obfuscation. Measured
   below.
2. **Weighted heuristics** (`maverick.safety.jailbreak_heuristics`) — a scorer
   wired into `safety.remote_scan` that catches softer phrasings the regex
   misses.
3. **Optional LLM cascade** (`MAVERICK_CASCADE_SHIELD=1`) — a model judge for
   ambiguous cases. Higher recall, costs a call; off by default.
4. **Full agent-shield SDK** — a separate, larger rule set that is not
   published (it is not on PyPI and not vendored in this repository). The
   shield uses it only when it is installed, so the built-in rules above are
   what ships and what runs. It is not measured here.
5. **Action-layer containment** — the part most "AI safety" layers lack. Even
   when text detection misses, the *action* is bounded:
   - writes through connectors and the `database` tool are **confirm-gated**
     (a dry run until `confirm=true`) — so "drop every table" / "POST to C2"
     can't execute unattended;
   - shell is **sandbox-mediated** (`sandbox.exec()`), never a raw
     `subprocess` from a tool;
   - agents run under **scoped capabilities** (sub-agents can only narrow, never
     widen) and a hard **budget cap** (`budget.check()`);
   - the audit log is **hash-chained and Ed25519-signed** (on by default) for
     tamper-evident evidence.

   In the held-out benchmark below, the action-abuse misses
   (`destructive_action`, `privilege_escalation`, `sandbox_escape`) are exactly
   the cases this layer contains: the dangerous step requires confirmation or a
   capability the agent doesn't hold, regardless of the text slipping past the
   regex.

## What the offline fallback actually scores

Methodology (baked into the harness so it can't drift):

- **Three splits.** `train` is the corpus the regex was tuned on — a high score
  there proves *no regression*, not skill. `heldout` is novel phrasings the
  rules were never edited for — **this is the real capability signal**. `benign`
  is agent-realistic non-attacks, including false-positive bait (attack
  vocabulary in innocent contexts), which sets the FPR floor.
- **Wilson 95% confidence intervals** on every rate (the held-out set is
  intentionally small; the CI keeps us honest about that).
- **Evasion sweep**: each held-out attack is re-tested under zero-width,
  full-width, homoglyph, and base64 obfuscation.
- **Leakage guard** (`detector_score.train_overlap`): any external prompt that
  normalizes to a trained-on phrase is dropped before scoring.

The table below is the 2026-07-29 snapshot generated into
`benchmarks/security/RESULTS.md`
artifact from the current corpus (53 train / 31 held-out / 32 benign):

| backend | TPR train¹ | TPR held-out (95% CI) | FPR benign (95% CI) | F1 held-out |
|---|---|---|---|---|
| `builtin@high` | 18.9% | 71.0% [53–84] | 6.2% [2–20] | 0.800 |
| `builtin@medium` | 20.8% | 83.9% [67–93] | 6.2% [2–20] | 0.881 |
| `defense_in_depth`² | 75.5% | 83.9% [67–93] | 9.4% [3–24] | 0.867 |

¹ Regression check only. ² Regex `OR` weighted heuristics — the realistic
posture when the SDK is absent.

Evasion (held-out TPR, `defense_in_depth`): zero-width 71.0%, full-width 71.0%,
homoglyph 71.0%, base64 100% (the base64 path de-obfuscates and re-scans).

### Read this honestly

The offline fallback is a **tripwire, not the primary defense**. This small,
repository-authored held-out set currently measures 71.0% for `builtin@high`
and 83.9% for the combined posture, but five held-out cases still miss and the
confidence intervals are wide. These values are a reproducible
diagnostic, not a generalized recall claim. Real deployment safety also
depends on confirmation gates, capabilities, sandbox isolation, budget limits,
and egress controls. A credible headline efficacy number requires pinned
external held-out sets plus end-to-end attack-success-rate measurement.

Current held-out misses and false positives are listed in
`benchmarks/security/RESULTS.md`
(regenerated with each run) so the gaps are tracked, not forgotten.

## Latency & ReDoS are a hard CI gate

A scan that hangs is a detection *bypass*, not a perf nit:
`packages/maverick-shield/tests/test_scan_latency_gate.py` fails the build if a
hot-path scan exceeds its budget on adversarial input. `latency_bench.py`
reports the p50/p95/p99/max distribution.

## Reproduce it

```bash
python benchmarks/security/detector_score.py     # accuracy table + RESULTS.md
python benchmarks/security/latency_bench.py        # latency distribution
```

No API key, no SDK, no network. The corpus (`benchmarks/security/corpus.py`)
carries no encoded blobs — obfuscated variants are built at runtime.

## Training a probe model

The cheap-probe tier can load an operator-trained linear model
(`[shield] probe_model` or `MAVERICK_SHIELD_PROBE_MODEL`). It is off by default
and is combined with the heuristic by MAX, so a model can only raise recall.
The offline trainer fits an L2 logistic regression over the same feature
extractor that inference uses and exports the JSON artifact the shield loads
(`{bias, weights, threshold, ngram_buckets, ngram_sizes}`):

```bash
python -m maverick_shield.probe_train --corpus data.jsonl --out model.json \
    --ngram-buckets 256 --max-fp 0.01
```

The corpus is JSONL (`{"text", "label"}` or the red-team `{"text", "expected"}`
shape) or plain text with one attack prompt per line. `--ngram-buckets` adds
hashed character n-gram features so a model can carry lexical content; `0`
keeps the seven fixed signals only. `--max-fp` sets the benign false-positive
ceiling used to choose the threshold.

Public datasets whose licences permit use in a model you distribute:

| Dataset | Approximate size | Licence | Benign negatives |
|---|---|---|---|
| [guychuk/benign-malicious-prompt-classification](https://huggingface.co/datasets/guychuk/benign-malicious-prompt-classification) | 465K rows | Apache-2.0 | Yes |
| [TrustAIRLab/in-the-wild-jailbreak-prompts](https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts) | 1.4K jailbreak, 13.7K regular prompts | MIT | Yes |
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | 662 rows | Apache-2.0 | Yes |
| [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | 1.3K rows | Apache-2.0 | Yes |
| [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | 1K rows | MIT | No (injections only) |

Do not train a distributed model on non-commercial data such as
`rogue-security/prompt-injections-benchmark` (CC-BY-NC-4.0) or on sets with no
licence tag such as `JasperLS/prompt-injections`; `deepset/prompt-injections`
carries the same rows under Apache-2.0. Record each dataset's name, licence and
revision alongside the artifact.

Before enabling a model by default for a deployment:

- Split train and test sets by source and attack family, not by random rows,
  and remove near-duplicate prompts first, so templated jailbreaks do not leak
  into the test set.
- Add hand-picked hard negatives: security documentation, CVE write-ups,
  base64 and hex code snippets, and non-English or emoji-heavy text.
- Measure the MAX ensemble (model or heuristic) on benign text the model never
  saw. It should keep the benign false-positive rate at or below 1% while
  raising recall over the heuristic alone.

## What a published recall number needs

The credible public recall figure comes from scale and end-to-end measurement:
external held-out sets (AgentDojo, JailbreakBench) run through the leakage
guard, and an end-to-end AgentDojo run measuring attack-success-rate reduction
with the shield **on vs. off** (the number that actually matters: not "did we
flag the string" but "did the agent get compromised"). That axis needs an LLM
budget and is tracked, not claimed.
