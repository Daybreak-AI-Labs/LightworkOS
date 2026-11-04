---
name: llm-eval-harness-build
triggers:
  - build llm eval
  - ragas harness
  - llm judge eval
  - llm regression gate
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

This skill scaffolds an evaluation harness for an LLM feature so prompt and model changes can be judged before they ship: a curated golden dataset, task-appropriate metrics (exact/structural checks where possible, LLM-as-judge rubrics for open-ended outputs, and RAGAS-style retrieval metrics for RAG — faithfulness, answer relevance, context precision/recall), and the wiring to run it both offline (CI regression gate) and online (sampled production). It turns "the new prompt feels better" into a measured, reproducible comparison. The output is a harness scaffold, dataset schema, and rubric/metric definitions staged for review; it does not promote a model, change the production prompt, or merge anything.

# Steps

1. Use read_file and knowledge_search to understand the feature: the task type (extraction, summarization, RAG Q&A, classification, agentic), the current prompt/model, known failure modes, and what "good" means to stakeholders. Decide which outputs can be checked deterministically vs which need a judge.
2. Build the golden set: a representative, versioned dataset of inputs with expected outputs or reference answers, deliberately including known-hard and past-failure cases; document how it was sampled and keep it separate from any training/few-shot data to avoid leakage.
3. Define the metrics: deterministic assertions (JSON schema valid, required fields present, regex/field match) first; an LLM-as-judge rubric with explicit, low-variance scoring criteria for open-ended quality; and for RAG, the RAGAS metrics (faithfulness, answer relevancy, context precision/recall). Specify the judge model and rubric so scores are reproducible.
4. Scaffold the harness to run the suite over the golden set, emit per-metric scores and a diff vs the current baseline, and wire it as a CI regression gate (fail the change if a metric regresses past a threshold) plus an online sampler for production traffic. Stage it for review; mark that promoting a model/prompt and setting the pass thresholds are human decisions.

# Notes

Prefer deterministic checks to a judge wherever the task allows (schema/field/exact match) — they are cheaper, reproducible, and not themselves a model that can drift; reserve LLM-as-judge for genuinely open-ended output and pin the judge model + rubric so its scores are stable. The golden set is the asset: version it, include hard and previously-failed cases, and keep it out of the prompt's few-shot examples or you measure leakage, not quality. RAG needs retrieval metrics (RAGAS faithfulness/context precision) separate from answer-quality metrics — a right answer over wrong context is still a bug. This skill builds and stages the harness; it does not promote a model, edit the live prompt, or merge — humans set thresholds and ship. Treat the judge as fallible: spot-check its scores against human labels before trusting the gate.
