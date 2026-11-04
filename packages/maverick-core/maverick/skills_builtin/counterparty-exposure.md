---
name: counterparty-exposure
triggers:
  - counterparty exposure
  - bank risk concentration
  - how much are we exposed to this bank
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Measures the firm's aggregate financial exposure to each counterparty (banks, brokers, money-market funds, derivative dealers) across deposits, investments, undrawn facilities, and mark-to-market derivative positions. Produces a concentration analysis that ranks exposures against approved limits and flags breaches and near-breaches for action.

# Steps

1. Pull positions per counterparty from the relevant sources with `sql_query`: cash deposits, MMF holdings, securities, repo, and derivative MTM plus collateral. Capture the legal counterparty name and parent/group so subsidiaries roll up correctly; normalize aliases.
2. Pull each counterparty's approved limit and current credit rating (and any guarantor) from the limits/master-data table. Mark counterparties with no limit on file as `unlimited - exception`.
3. Aggregate net exposure per counterparty and per parent group in `spreadsheet`: sum across instruments, net collateral where legally enforceable (cite the netting basis), and express each as a % of the limit and of total portfolio.
4. Rank by exposure, flag every limit breach and any utilization above the warning threshold (e.g. 85%), and note rating downgrades since last review. Report the analysis with recommended limit actions (reduce, diversify, escalate) as recommendations; state assumptions (netting enforceability, ratings as-of date, unverified positions) and hand off to risk/treasury for decision.

# Notes

Wrong if subsidiaries are not rolled into the parent group (understates concentration), if collateral is netted where it is not legally enforceable, or if undrawn committed facilities are omitted. Ratings and limits must be cited with an as-of date; flag stale data rather than trusting it. This skill recommends limit changes — it never reallocates positions or closes lines; a human approves. Not for market/VaR risk or for non-financial trade-credit exposure.
