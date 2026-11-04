---
name: inventory-abc-xyz
triggers:
  - abc xyz
  - inventory classification
  - stocking policy
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Classifies SKUs on two axes — ABC by annual consumption value and XYZ by demand variability (coefficient of variation) — and maps each of the nine cells to a recommended stocking policy. Produces an ABC-XYZ matrix and a per-SKU policy assignment for inventory and planning teams to act on.

# Steps

1. Query the real transaction data with sql_query: per-SKU annual usage quantity, unit cost, and a per-period demand series over a consistent window (e.g. 12 monthly buckets). Confirm the window and that costs are current — stale unit costs distort the value ranking.
2. Compute annual consumption value (usage * unit cost) per SKU. Rank descending, take the cumulative share, and assign A/B/C by Pareto cutoffs (typical A ~80% of value, B next ~15%, C ~5%) — state the exact cutoffs used; they are a choice, not a law.
3. Compute demand variability per SKU as coefficient of variation (std / mean of the period series). Assign X (low/steady, e.g. CV < 0.5), Y (moderate, 0.5–1.0), Z (high/erratic, > 1.0). State the CV thresholds; flag SKUs with too few periods as unclassifiable.
4. Cross the two axes into a 9-cell matrix and attach a stocking policy per cell (e.g. AX = tight continuous review, high service; CZ = make-to-order / minimal stock or review for delisting). Hand off the matrix and per-SKU assignments, reporting cutoffs, the window, and any unclassified SKUs.

# Notes

Wrong if the demand window is too short for a meaningful CV, if cutoffs are applied to quantity instead of value, or if seasonal SKUs are read as "erratic" Z when they are actually predictable seasonal — note seasonality separately. Policies are recommendations: delisting C/Z items or cutting safety stock on A items is irreversible and must be approved by a human. Do not use as the sole basis for purchasing decisions; pair with lead-time and supplier constraints.
