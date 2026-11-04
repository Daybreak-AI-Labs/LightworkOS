# Security benchmarks

Capability benchmarks live one level up (`benchmarks/`). This directory
measures the **shield** — the safety detection layer — on two axes that a
security benchmark must cover: **detection accuracy** and **hot-path latency**.
It scores the built-in fallback shield, which is what runs when the
agent-shield SDK is not installed, so its numbers are reproducible in-repo.

## What's here (offline, no SDK, no API key)

| File | What it does |
|---|---|
| `corpus.py` | Labelled dataset: `train` (the existing regression corpus the rules were tuned on), `heldout` (novel attacks authored here), `benign` (agent-realistic, incl. false-positive bait). Obfuscations are built at runtime — no encoded blobs in source. |
| `detector_score.py` | Scores every offline backend → TPR/FPR/F1 with Wilson 95% CIs, an evasion sweep, and a leakage guard. Writes `RESULTS.md`. |
| `latency_bench.py` | Per-scan p50/p95/p99/max for the hot-path scanners on adversarial input. |
| `end_to_end_asr.py` | Routes each labelled attack through the Shield chokepoint the agent uses for that attack class and reports attack-success-rate reduction. Writes `RESULTS_E2E.md`. |
| `RESULTS.md`, `RESULTS_E2E.md` | Generated, checked-in (`source=measured`). |

The pass/fail **CI gate** for latency/ReDoS lives with the shield:
`packages/maverick-shield/tests/test_scan_latency_gate.py`. A scan that
times out **fails the build** — a hung scan that fails open is a *detection
bypass*, not a perf nit.

```bash
python benchmarks/security/detector_score.py     # accuracy dashboard + RESULTS.md
python benchmarks/security/latency_bench.py       # latency distribution
python benchmarks/security/end_to_end_asr.py      # chokepoint ASR reduction + RESULTS_E2E.md
```

## Read the numbers honestly

- **`train` TPR is a regression check, not skill.** The built-in rules were
  hand-tuned on that corpus (e.g. `persona_takeover` was widened *because* a
  corpus case slipped past it). A high train TPR only means "no regression."
- **`heldout` TPR / F1 is the capability signal**, with the important limit
  that this is a small, repository-authored split. `RESULTS.md` is the
  authoritative current artifact; docs may reproduce it only with its corpus,
  confidence intervals, and internal-diagnostic caveat.
- **This dashboard is not a generalized marketing efficacy figure.** A
  credible headline number requires pinned external held-out data and an
  end-to-end run against a live agent (see below).
- Backends needing the SDK or an LLM are listed as **UNAVAILABLE**, never
  silently dropped.

## External held-out data (needs network and an API budget)

External held-out sets (AgentDojo, JailbreakBench) add scale, and an
end-to-end AgentDojo run (shield ON vs OFF) measures attack-success-rate
reduction against a live agent. Neither runs in this directory.
**Never vendor HarmBench/AdvBench payloads** — reference by ID, pull on
demand, and run candidates through `detector_score.train_overlap()` first so a
trained-on phrase can't inflate the score.
