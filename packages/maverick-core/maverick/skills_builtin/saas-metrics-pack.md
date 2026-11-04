---
name: saas-metrics-pack
triggers:
  - compute our saas metrics
  - what is our ARR and NRR
  - CAC payback and magic number
  - saas metrics pack
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Computes and explains the core SaaS operating metrics — ARR/MRR, net revenue retention (NRR), CAC payback, and the magic number — from billing, subscription, and sales-and-marketing-spend data. Produces a single metrics pack with each value, the exact formula used, and the period it covers, so finance can read it without re-deriving definitions.

# Steps

1. Establish the source tables and period grain via `sql_query`: the subscription/recurring-revenue table (for ARR/MRR), the cohort-level expansion/contraction/churn movements (for NRR), and S&M spend plus new-ARR by period (for CAC payback and magic number). Confirm currency and whether amounts are normalized to annual.
2. Compute the recurring base with `sql_query`: month-end MRR and ARR (MRR × 12), excluding one-time and services revenue. State explicitly which revenue lines are included so the ARR definition is auditable.
3. In `spreadsheet`, compute each metric with its formula visible: NRR = (starting ARR + expansion − contraction − churn) / starting ARR for a fixed cohort over the window; CAC payback = S&M spend in period / (new ARR in period × gross margin), in months; magic number = net new ARR in period (annualized) / prior-period S&M spend. Keep the inputs to each on the same sheet.
4. Assemble the pack: each metric, its value, formula, period, and data source; flag any metric whose inputs were estimated (e.g. gross margin assumed, partial-period spend) as an assumption. Hand off with a note that definitions should be confirmed against the company's own metric policy before external use.

# Notes

The pack is wrong if ARR silently includes services/one-time revenue, if NRR mixes new-logo revenue into the retention cohort (it must measure only the starting cohort), or if CAC payback omits gross margin or mismatches the spend and new-ARR periods. Magic number is sensitive to lead/lag between spend and bookings — state the convention used. These are management metrics, not GAAP revenue; do not reconcile them to the income statement. A human owns the definitions; this skill recommends values, it does not set policy. Not for non-recurring or usage-only revenue models where ARR/NRR are ill-defined.
