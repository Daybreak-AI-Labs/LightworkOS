---
name: customer-health-score
triggers:
  - health score
  - customer health
  - adoption score
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Designs a transparent, weighted customer health-score model from observable account signals. Produces a signal inventory, per-signal scoring rules, category weights, and red/yellow/green thresholds that map a raw composite to an interpretable health tier. This is a model design artifact, not a deployed scoring job.

# Steps

1. Inventory candidate signals with `sql_query` against product, support, and revenue tables — group into categories (adoption/usage, engagement, support, commercial, sentiment). For each, confirm the data actually exists and note coverage; drop or flag signals with sparse population rather than scoring on nulls.
2. Define a scoring rule per signal grounded in real distributions: pull the metric's quartiles/percentiles and set band cutoffs from them, normalizing each signal to a common scale (e.g., 0-100). Document the direction (higher usage = healthier; rising tickets = unhealthier).
3. Assign category weights that sum to 100, justifying each by its expected link to retention/expansion, and compute the composite. Set red/yellow/green thresholds and back-test them against known recent outcomes (churned vs. renewed/expanded accounts) to check the tiers separate them.
4. Deliver the model in a `spreadsheet`: signal inventory (signal, source, coverage, direction), scoring bands, weights, composite formula, thresholds, and the back-test separation result. Hand off to the CS leader, stating which weights are evidence-based vs. assumed and recommending a validation window before the score drives action.

# Notes

Wrong if signals are scored on missing data (treats absence as a value), weights are guessed without back-testing, or thresholds don't separate real outcomes (an un-validated green tier that still churns is worse than no score). Coverage gaps bias the composite toward whichever signals happen to be populated — surface coverage explicitly. This is a design recommendation; a human owns adopting it and any automation it feeds. Do NOT present an un-back-tested model as production-ready, and do NOT use it as a churn predictor — a health score is a heuristic, not a calibrated probability.
