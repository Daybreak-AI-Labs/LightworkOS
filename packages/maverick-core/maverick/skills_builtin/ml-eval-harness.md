---
name: ml-eval-harness
triggers:
  - ml eval
  - model evaluation
  - build an eval harness
tools_needed:
  - code_exec
  - knowledge_search
---
# What this skill does

Designs and stands up a repeatable evaluation harness for an ML model. Takes the model's task and quality bar, then assembles held-out datasets, the metrics that map to the task, baselines to beat, and runnable code that scores a model and emits a comparable report. Output is an eval harness — datasets, metric definitions, baseline numbers, and a runner — that produces the same verdict on every run.

# Steps

1. Define the task and the decision the eval informs (ship gate, regression check, model comparison). Use `knowledge_search` to find existing eval sets and metric conventions for this task; reuse a frozen held-out set and confirm it never overlapped training data.
2. Choose metrics that match the task and failure costs (e.g. precision/recall at an operating threshold, calibration, latency), not just a single accuracy number. Define each metric precisely enough that two people compute it identically.
3. Establish baselines: a trivial baseline (majority/random/heuristic) and the current production model. With `code_exec`, implement the runner so it scores model + baselines on the same data, fixes the random seed, and writes metrics with the dataset version and commit.
4. Run the harness, sanity-check that baselines reproduce known numbers, then report the design and results — including slice breakdowns. State assumptions (dataset is representative, labels are trusted) and mark any metric whose ground truth is noisy or unverified.

# Notes

The harness is wrong if the eval set leaked into training (inflated scores), if results aren't reproducible (no fixed seed / unversioned data), or if a single aggregate metric hides a regression on a critical slice — always report against a baseline so a number has meaning. Stage the harness and its verdict for a human gate; it informs a ship decision but does not auto-promote a model. Do NOT use for live production monitoring (use drift/online metrics there) — this is offline, point-in-time evaluation.
