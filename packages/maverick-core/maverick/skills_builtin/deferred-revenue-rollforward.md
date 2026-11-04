---
name: deferred-revenue-rollforward
triggers:
  - roll deferred revenue forward
  - deferred revenue rollforward
  - contract liability schedule
  - deferred roll for the quarter
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Builds a period-over-period deferred revenue (contract liability) rollforward: opening balance + new billings/deferrals − revenue recognized ± adjustments = closing balance, with a waterfall reconciling each line. Produces an auditable schedule that ties the GL deferred-revenue account to the recognized-revenue stream for a stated period.

# Steps

1. Pull the opening deferred balance as of the period-start date from the GL/contract table via `sql_query` (filter on the contract-liability account and the as-of date). Record the exact query and source table so the number is traceable, not asserted.
2. Pull the period's movements with `sql_query`: new billings/deferrals (invoices booked to deferred), revenue recognized (releases out of deferred), and any adjustments (refunds, reclasses, FX, contract mods) — each as a separate, labeled bucket. Do not net buckets together.
3. In `spreadsheet`, assemble the rollforward: Opening + Additions − Recognized ± Adjustments = Closing. Independently compute Closing from the source GL balance at period-end and assert the two agree; flag any residual as an unreconciled tie-out variance rather than forcing it to zero.
4. Build the waterfall view (opening → each movement → closing) and report it, stating the period, source tables/queries used, and any unreconciled variance or estimated/manual buckets as assumptions for a human to confirm before the schedule is used in close or filings.

# Notes

The output is wrong if buckets double-count (e.g. a contract mod counted as both an adjustment and a re-billing) or if the period boundaries on the opening and closing queries don't match the movement window. A non-zero tie-out variance is a finding, not something to plug — surface it. Recognized-revenue figures must come from the recognition schedule, not be inferred from billings. This is a draft reconciliation: do not post journal entries or true-up the GL; a controller approves any adjusting entry. Not for cash-basis books or single-period one-off invoices with no deferral.
