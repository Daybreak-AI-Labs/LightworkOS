---
name: sales-forecast-rollup
triggers:
  - forecast rollup
  - sales forecast
  - commit roll
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Rolls up an individual-rep sales forecast into a team/segment view for a given period and produces a rollup showing pipeline coverage, weighted and committed amounts, and the deals carrying the most risk. Output is a decision-support summary for a forecast call, not a system-of-record update.

# Steps

1. Query the CRM/warehouse with sql_query for open opportunities in the target period: rep, amount, stage, forecast category (commit/best-case/pipeline), close date, and last-activity date. State the period boundaries and snapshot timestamp you queried.
2. Aggregate in the spreadsheet tool by rep and roll up to team: sum commit, best-case, and total pipeline; compute weighted forecast using stage probabilities (cite the probability source); compute coverage = total pipeline / quota.
3. Identify risk: flag commit deals that are slipping (close date past or pushed), stale (no recent activity), or single-deal-concentrated, and quantify how much commit is at risk.
4. Report the rollup table (per rep and team total) with coverage, weighted, commit, and a ranked risk list; state assumptions (probability model, snapshot time) and hand off to the forecasting manager. Do not overwrite any rep's submitted number in the CRM.

# Notes

The rollup is wrong if it mixes periods or double-counts split/multi-rep deals — dedupe on opportunity ID and confirm the period filter. Coverage is meaningless without the correct quota; if quota is missing, report raw amounts and mark coverage unavailable. Probabilities are an analytic overlay, not the rep's commit; never present weighted as committed. This skill recommends; changing forecast categories or quota is a human/CRM action. Do not use it for closed-won revenue reporting (that's a finance actuals task).
