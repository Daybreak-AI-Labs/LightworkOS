---
name: demand-forecast-reconciliation
triggers:
  - forecast reconciliation
  - consensus forecast
  - forecast bias
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Reconciles competing demand forecasts (e.g. statistical baseline, sales, marketing, finance) into a single consensus forecast per item/period. It quantifies each input's historical accuracy and directional bias, blends them into a defensible consensus, and produces an auditable override log so every deviation from the statistical baseline is traceable. Output is a consensus forecast table with bias and MAPE metrics plus the override record.

# Steps

1. Pull each forecast stream and matching actuals at the same grain (item x location x period) via `sql_query`. Confirm grain and unit alignment before joining; mismatched grain silently corrupts every metric downstream.
2. For each stream over the backtest window compute MAPE (and bias as mean signed percentage error) against actuals. Exclude periods with missing actuals and report the coverage so metrics aren't read as more complete than they are.
3. Form the consensus per item/period (accuracy-weighted blend or the lowest-bias stream, stated explicitly) in the `spreadsheet`. Where a stakeholder override replaces the consensus, capture old value, new value, owner, and stated reason.
4. Validate consensus against any hard constraints (non-negative, capacity/allocation ceilings) and recompute consensus MAPE/bias on the backtest to confirm it beats the individual streams.
5. Report the consensus table with per-stream and consensus MAPE/bias, the override log, and assumptions (window, weighting method, exclusions). Note that the consensus is a recommendation — demand planning sign-off is required before it feeds supply/financial plans.

# Notes

Output is wrong if grain or units are misaligned, if MAPE is computed over periods with missing actuals without disclosure, or if overrides bypass the log (an unlogged override destroys auditability — the whole point). Distinguish bias (systematic over/under) from MAPE (magnitude); a low-MAPE stream can still be biased. Do not auto-commit the consensus to the planning system; it is staged for human approval. Not for new-product or intermittent-demand series where MAPE is unstable — flag and use a different accuracy metric instead.
