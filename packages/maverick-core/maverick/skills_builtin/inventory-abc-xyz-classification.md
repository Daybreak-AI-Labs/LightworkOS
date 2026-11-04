---
name: inventory-abc-xyz-classification
triggers:
  - abc xyz analysis
  - inventory classification
  - which SKUs should we stock differently
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Classifies every SKU on two axes — ABC (annual consumption value) and XYZ
(demand variability) — and emits a 3x3 matrix that maps each SKU class to a
recommended stocking policy. Output is an ABC-XYZ matrix plus per-class policy
recommendations (review cadence, buffer posture, automation level).

# Steps

1. Pull per-SKU demand history with `sql_query`: SKU, period (>=12 months of
   buckets), units consumed, unit cost. Reject SKUs with under 6 periods of
   data — mark them "insufficient history", do not classify them.
2. ABC axis: compute annual consumption value (units x unit cost) per SKU, sort
   descending, take the cumulative-percent-of-total. Cut A = top ~80% of value,
   B = next ~15%, C = final ~5% (state the exact thresholds you used).
3. XYZ axis: compute coefficient of variation (stddev/mean of demand per period)
   per SKU. Cut X (CV < 0.5, stable), Y (0.5–1.0, variable), Z (>1.0, erratic).
   State thresholds; they are conventions, not law — flag if data argues for
   different cuts.
4. Cross the two axes into a 9-cell matrix in the `spreadsheet`. Attach a policy
   per cell (e.g. AX = tight, automated min/max; CZ = make-to-order / review for
   delisting). Report the matrix, the thresholds assumed, and the count of
   unclassified SKUs; hand off for a planner to approve policy changes.

# Notes

Wrong if the demand series mixes units and value, ignores seasonality (a strong
seasonal SKU looks erratic on raw CV — note it, don't silently bucket it Z), or
if returns/cancellations inflate consumption. Thresholds are tunable
conventions; surface them, never bury them. Policy recommendations are a draft —
delisting, MOQ changes, and automation rollout are business decisions a human
owns. Do not use for new SKUs with no history; use NPI forecasting instead.
