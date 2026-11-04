---
name: pql-scoring-model
triggers:
  - build pql model
  - score product qualified leads
  - activation scoring
tools_needed:
  - sql_query
  - spreadsheet
  - knowledge_search
---
# What this skill does

This skill defines a product-usage scoring model that turns activation milestones, usage depth, breadth, and account fit into a Product-Qualified Lead/Account (PQL/PQA) score, backtests it against historically closed-won deals, and emits routing thresholds. It is recommend-only: it proposes a scoring rubric and cutoffs for human approval and never auto-assigns leads to reps or fires outreach.

# Steps

1. Use knowledge_search to gather the existing activation definition, ICP/fit criteria, and any prior lead-scoring scheme so the model extends rather than contradicts the agreed activation moment.
2. Use sql_query to assemble per-account features from product telemetry: activation-milestone completion, usage depth (frequency/recency), breadth (distinct features/seats), and fit attributes (firmographics, plan), aligned to a point in time so no post-conversion signal leaks in.
3. Use spreadsheet to define a transparent weighted score (or scored bands per feature), then backtest: rank historical accounts by the score and measure conversion lift to closed-won by decile, checking the score separates winners from non-winners.
4. Propose routing thresholds (PQL / PQA / hold) calibrated to capacity and observed conversion, document each feature's weight and rationale, and stage the rubric for RevOps approval — recommend the cutoffs, do not enforce them.

# Notes

Beware leakage: features computed after the conversion event (e.g. seats added post-purchase) will look predictive in backtest and fail live — align every feature to the pre-conversion point in time. Keep the model interpretable so reps trust it; an opaque score nobody can explain gets ignored. A score that ranks well historically can still drift, so recommend a review cadence rather than a set-and-forget cutoff. This skill recommends thresholds only; routing and outreach remain human-owned actions.
