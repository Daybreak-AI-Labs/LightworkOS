---
name: budget-variance-analysis
triggers:
  - budget variance analysis
  - actuals vs budget
  - variance bridge
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Explains why actual results differ from budget (or forecast) by decomposing the total variance into price, volume, and mix effects plus cost drivers. Produces a variance bridge that walks budget to actual with each driver quantified and labeled favorable or unfavorable.

# Steps

1. Pull budget and actual figures from the source of record (sql_query the financial/planning tables or read the provided budget file) at a consistent grain — by product, region, or line item — for the same period. Reconcile that budget and actual totals each foot before decomposing.
2. Compute the total variance per line and tag favorable/unfavorable from the P&L perspective (revenue up = favorable; cost up = unfavorable). Do not net offsetting variances away — keep them visible.
3. Decompose the revenue variance: volume = (actual qty - budget qty) x budget price; price = (actual price - budget price) x actual qty; mix = the residual from shifts in product/segment weighting. Decompose cost variances into rate vs. usage. Confirm the components sum back to the total variance (bridge reconciles to zero residual).
4. Report the deliverable: a price/volume/mix bridge from budget to actual, the top drivers ranked by magnitude, and a short narrative per driver grounded in the data. State the decomposition convention used and mark any driver attribution that is inferred rather than sourced as unverified.

# Notes

The output is wrong if the price/volume/mix components do not sum to the total variance — always show the reconciliation and chase any residual (usually a grain mismatch or a missing FX/timing effect). Mix is the classic trap: compute it as the residual after a consistent price-then-volume (or volume-then-price) order and state which order you used, since the split is convention-dependent. Comparing against a stale or re-baselined budget invalidates the bridge — confirm the budget version. This is explanatory and advisory; reforecasting or accountability actions are decided by a human, not triggered here.
