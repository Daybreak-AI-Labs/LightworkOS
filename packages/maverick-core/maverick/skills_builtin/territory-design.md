---
name: territory-design
triggers:
  - design balanced sales territories
  - territory carving for the new fiscal year
  - even out account coverage across reps
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Carves a flat account/geography list into balanced sales territories optimized on one or more capacity metrics (account count, pipeline $, named-account weight, drive-time/region). Produces a territory assignment table plus a balance-and-coverage analysis showing variance across territories and any unassigned or over-loaded segments. Output is a draft proposal for RevOps review, not a system mutation.

# Steps

1. Pull the account universe with `sql_query`: account_id, region/postal, segment, ARR/pipeline, current owner, and any "named" or strategic flag. Confirm the row count matches the expected book of business; flag accounts with null region or null value before they silently distort balance.
2. Establish the design inputs from the request: number of territories (or reps), the primary balance metric, hard constraints (named accounts pinned to a rep, region contiguity, do-not-move accounts), and the acceptable imbalance tolerance (e.g. ±10% on the primary metric).
3. Assign accounts to territories honoring hard constraints first, then greedily balance the primary metric; in `spreadsheet`, compute per-territory totals for every metric (count, $, named weight) and the % deviation from the mean. Iterate moves only on movable accounts until all territories sit inside tolerance or you hit a documented blocker.
4. Produce the assignment table plus a balance summary (per-territory metrics, min/max/spread, Gini or simple variance) and a coverage check (unassigned accounts, white-space regions, single-rep overconcentration). Hand off as a recommendation, stating the metric weights and tolerance used and listing any account that could not be balanced without violating a constraint.

# Notes

The output is wrong if territories balance on count but not on value (or vice versa) — always report every metric, not just the one optimized. Null regions/values and stale ownership are the top corruptors; surface them rather than imputing. Contiguity and named-account pins are business rules, not suggestions; never break a stated hard constraint to hit a balance target — escalate the conflict instead. This is a draft: rep assignments, comp implications, and CRM territory changes are irreversible-ish and belong to a human. Do not use for single-rep books or when headcount/quota is still unset — there is nothing to balance against.
