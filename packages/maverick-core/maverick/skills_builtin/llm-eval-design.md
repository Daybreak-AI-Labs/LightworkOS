---
name: llm-eval-design
triggers:
  - llm eval
  - llm testing
  - model comparison
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a repeatable evaluation for an LLM task or a head-to-head model comparison. Produces a labeled task set, a scoring rubric (deterministic checks plus, where needed, an LLM-judge protocol), and a decision rule that turns scores into a pass/ship call. The output is an eval spec someone can run and re-run, not a one-off vibe check.

# Steps

1. Pin the eval target with knowledge_search: the task, the candidate model(s)/prompt(s) under test, what "good" means, and any existing examples or production logs usable as test cases. Note the sample size you actually have and whether it covers the real input distribution — flag gaps rather than papering over them.
2. Assemble the task set: representative cases plus deliberate hard/edge/adversarial cases, each with an expected answer or acceptance criteria. Prefer deterministic graders (exact match, schema validation, regex, numeric tolerance, retrieval hit) wherever the task allows, since they are cheap and reproducible.
3. For open-ended outputs, define an LLM-judge protocol: a rubric with named criteria and a scale, the judge prompt, pairwise-vs-pointwise choice, and bias controls (randomize/swap order, blind to which model produced which output). State the judge model and that judge scores need spot-check calibration against human labels.
4. Define the decision rule (aggregate metric, threshold, and tie-breaking) and report format. Hand off the spec, state assumptions (sample size, judge reliability), and mark the ship/no-ship verdict as a recommendation for a human — the eval informs the call, it does not auto-promote a model.

# Notes

The eval misleads if the task set is too small or unrepresentative (a green run on 10 easy cases proves nothing), if an LLM judge is trusted without calibration against humans, or if judge order/position bias is left uncontrolled. Deterministic checks beat a judge whenever the answer is checkable — reach for a judge only for genuinely open-ended output. Results are advisory: a passing eval recommends shipping; a human owns the decision. Not for live production monitoring (use ml-monitoring-design) or for authoring the prompt itself (use llm-prompt-design).
