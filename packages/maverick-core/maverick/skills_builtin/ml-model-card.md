---
name: ml-model-card
triggers:
  - model card
  - model documentation
  - document this ml model
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a model card documenting a trained ML model for reviewers, deployers, and auditors. Takes the model's training artifacts and evaluation results and writes a structured card covering intended use, training data, evaluation metrics (overall and sliced), ethical considerations, and limitations. Output is a single review-ready model card grounded in the model's actual metrics — not aspirational claims.

# Steps

1. Gather the model's facts via `knowledge_search` over training configs, eval reports, and dataset docs: model type, version, training data provenance, evaluation datasets, and metrics. Record the source for each fact; mark anything you cannot find as "unknown" rather than inferring.
2. Write Intended Use and Out-of-Scope Use: the decisions this model is meant to support, the population it was trained on, and explicit uses to avoid. Ground these in the training distribution, not in optimistic generalization.
3. Fill Evaluation: headline metrics plus performance sliced across the subgroups that matter (demographics, segments, edge conditions), with the eval dataset and date for each. Include known failure modes and any fairness/safety findings.
4. Complete Limitations, Ethical Considerations, and Maintenance (owner, retrain cadence, monitoring), then report the card. State which sections rest on unverified or missing artifacts so a reviewer knows where the gaps are.

# Notes

The card is wrong if it reports only aggregate metrics while hiding a failing subgroup, cites metrics from a different model version, or states an intended use the evaluation does not support. Every metric must trace to a named eval run — never fabricate numbers or invent slices that weren't measured. This is documentation, not approval: a human owner signs off on deployment. Do NOT use as a substitute for the actual evaluation — if metrics don't exist yet, run an eval first.
