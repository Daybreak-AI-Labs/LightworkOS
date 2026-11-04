---
name: supplier-scorecard-build
triggers:
  - build a supplier scorecard
  - rate our vendors on quality and delivery
  - weighted vendor performance rating
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Builds a supplier performance scorecard from transactional data: pulls KPI inputs (on-time delivery, defect/PPM rate, quality acceptance, responsiveness, cost/price variance) per supplier over a period, normalizes them to a common scale, applies category weights, and computes a weighted total and tier rating. Produces a ranked scorecard table with each supplier's KPI scores, weighted total, and rating band.

# Steps

1. Confirm the supplier set, the scoring period, the KPIs with their weights (weights must sum to 100%), and the rating bands. If weights or bands are not provided, propose a standard set and state it explicitly rather than assuming silently.
2. Use sql_query to pull the raw KPI inputs per supplier for the period (deliveries vs on-time, receipts vs rejects/PPM, PO price vs quoted, ticket response times); record row counts and exclude suppliers below a minimum-volume threshold, flagging them as `insufficient data` rather than scoring them on noise.
3. Normalize each KPI to a 0-100 score against its target, apply weights to get the weighted total, and assign the rating band (e.g. Preferred / Approved / Conditional / At Risk).
4. Build the scorecard in the spreadsheet sorted by weighted total, and hand off, citing the data source and period, listing low-volume/excluded suppliers, and noting any KPI computed from incomplete data.

# Notes

The scorecard is wrong if weights don't sum to 100%, if a supplier with a handful of transactions is ranked beside high-volume ones, or if a KPI is filled from missing data instead of being flagged. Numbers are only as good as the source query — state the period and record counts so the rating is auditable. This skill computes and ranks; it does not authorize offboarding, contract changes, or sourcing moves — those are irreversible decisions a human owns. Do not use it when KPI definitions or targets are undefined, or to compare suppliers across mismatched periods.
