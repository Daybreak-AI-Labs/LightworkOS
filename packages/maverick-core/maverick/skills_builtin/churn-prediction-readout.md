---
name: churn-prediction-readout
triggers:
  - churn prediction
  - at risk customers
  - retention model
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Turns the raw output of an existing churn-prediction model (scores, drivers) into an actionable retention readout. Produces a ranked at-risk customer list with risk tiers, top churn drivers per account, and a recommended save play for each tier. This reads model output; it does not train or tune the model.

# Steps

1. Pull the latest scored records with `sql_query` from the model output table — verify the score timestamp is current (within the model's refresh cadence) and capture columns: account_id, churn_score, top_driver(s), ARR/MRR, renewal_date, owner. If the timestamp is stale, stop and flag it.
2. Tier accounts by score using the model's calibrated thresholds (or, if none exist, use score quantiles and label them as unvalidated cutoffs). Sort within tiers by revenue at risk so high-value accounts surface first.
3. For each tier, map the dominant churn drivers to a save play drawn from existing playbooks (e.g., low-usage -> enablement outreach; support-friction -> escalation; sponsor-loss -> re-champion). Keep plays concrete and owned by a named role.
4. Assemble the readout in a `spreadsheet`: at-risk list (account, score, tier, ARR, driver, renewal, owner, recommended play) plus a one-line summary of total revenue at risk per tier. Hand off to the CS/retention owner, stating the model version, score date, and which thresholds are calibrated vs. inferred.

# Notes

Wrong if scores are stale, thresholds are uncalibrated and presented as authoritative, or revenue figures aren't joined correctly (account_id mismatches silently drop high-value accounts — validate row counts after the join). Churn scores are correlational, not causal: the "driver" is a model attribution, not a verified reason — mark it as such. This is a recommend-only artifact; it stages save plays and prioritization for a human to approve. Do NOT use it to auto-trigger outreach, discounts, or contract changes, and do NOT use it when no scored model output exists (you'd be inventing risk) — build a health score first.
