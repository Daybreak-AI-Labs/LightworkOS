---
name: pareto-abc-analysis
triggers:
  - pareto
  - 80/20
  - abc analysis
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Identifies the vital few items that drive most of a distribution (revenue, defects, cost, inventory) and classifies every item into A/B/C tiers by cumulative contribution. Produces a ranked Pareto table, the cumulative-percentage curve, and explicit A/B/C cut points — so effort and control can be concentrated where they matter instead of spread evenly.

# Steps

1. Define the item dimension (e.g. SKU, customer, defect type) and the value measure (revenue, count, cost). Confirm the measure is additive and sign-consistent — mixing returns/refunds or negative values silently corrupts the cumulative curve; filter or flag them first.
2. sql_query the source to aggregate value per item over the chosen period, returning item plus total value. Cite the table/query and the date range; report the row count and total so the base is auditable.
3. In the spreadsheet, sort descending by value, then compute each item's % of total, the running cumulative %, and the cumulative item count %. This cumulative column is the Pareto curve.
4. Set A/B/C cut points (common: A ≈ top 80% of value, B next 15%, C last 5% — adjust to where the curve actually elbows, not blindly to 80/20). Tag each item, summarize tier counts and value shares, and hand off the ranked table with cut points and the recommended focus, stating the period and any excluded rows.

# Notes

The 80/20 split is an empirical observation, not a law — report the actual concentration the data shows; forcing a textbook ratio onto a flat or hyper-concentrated distribution misleads. Period choice changes the answer: a too-short window over-weights one-off spikes — note the window and consider whether seasonality distorts it. Watch for granularity errors (analyzing variants when the decision is at the parent level, or vice versa). The classification recommends where to focus control or attention; decisions to delist a C item or deprioritize a customer are human calls that need context this analysis doesn't capture. Don't use it when items aren't comparable on one additive measure.
