---
name: cohort-revenue-retention
triggers:
  - measure revenue retention by cohort
  - cohort revenue analysis
  - gross and net revenue retention
  - revenue retention curves
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Measures revenue retention by signup/start cohort and tracks each cohort's recurring revenue across subsequent periods, producing gross revenue retention (GRR) and net revenue retention (NRR) curves. Produces a cohort triangle (cohort × period) plus per-cohort GRR/NRR so expansion and churn dynamics are visible over time, not just in aggregate.

# Steps

1. Define the cohort key and period grain via `sql_query`: assign each account to a cohort by its first recurring-revenue period, then pull that account's recurring revenue for every subsequent period. Record how cohort membership is fixed (it must never change after assignment).
2. Build the cohort × period matrix with `sql_query` or `spreadsheet`: rows = cohorts, columns = months-since-start, cells = retained recurring revenue from that cohort's accounts only (no new logos enter a cohort later).
3. Compute retention per cohort-period in `spreadsheet`: GRR = (starting cohort revenue − contraction − churn) / starting, capped at 100% (no expansion credit); NRR = (starting + expansion − contraction − churn) / starting. Keep contraction, churn, and expansion as separate visible columns feeding both.
4. Report the cohort triangle plus GRR/NRR curves; flag thin or immature cohorts (small N, few periods) as low-confidence and note any accounts excluded (e.g. reactivations, mid-period start proration) as assumptions for a human to review.

# Notes

The analysis is wrong if new accounts leak into older cohorts, if reactivated/churned-then-returned accounts are double-counted, or if GRR is allowed to exceed 100% (that means expansion is contaminating the gross figure). Small recent cohorts are noisy — do not over-read a single high/low cell. Currency and proration conventions must be consistent across periods. This is a descriptive, draft analysis: it diagnoses retention, it does not forecast or trigger account actions; a human decides retention interventions. Not for businesses without a stable recurring-revenue grain.
