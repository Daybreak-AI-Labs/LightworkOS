---
name: dso-collections-analysis
triggers:
  - what's our DSO trending toward
  - run a collections analysis
  - show me the AR aging and at-risk accounts
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Diagnoses receivables health and surfaces where cash is stuck. It pulls open invoices, computes Days Sales Outstanding (DSO), buckets balances by aging band, flags at-risk accounts by concentration and delinquency, and produces a collections worklist. Output is a structured analysis a credit/collections owner can act on, not a generic dashboard.

# Steps

1. Pull the open-AR ledger via `sql_query`: per-invoice customer, invoice date, due date, original amount, amount outstanding, and trailing revenue for the DSO window. Confirm the as-of date and currency; if invoices span currencies, convert to a single reporting currency and note the rate source and date.
2. Compute DSO = (total AR / credit sales over the period) x days in period, using the same period for both terms (commonly trailing 90). Report the period basis explicitly and, if data allows, the prior-period DSO for trend direction.
3. In `spreadsheet`, bucket outstanding balances into aging bands (current, 1-30, 31-60, 61-90, 90+) by days past due. Compute each band's share of total AR and the weighted-average days past due.
4. Rank at-risk accounts by past-due balance and concentration (top accounts as a % of total AR); flag any account that is both large and slipping bands versus the prior pull. Build a collections worklist (account, balance, oldest open invoice, days past due, suggested next action).
5. Report DSO and trend, the aging distribution, the concentration/at-risk list, and the worklist. State assumptions (as-of date, DSO basis, FX treatment) and hand off; recommend dunning/escalation actions but do not send communications or place credit holds without a human approving.

# Notes

Output is wrong if the DSO numerator (AR) and denominator (credit sales) use mismatched periods or currencies, or if credit memos/unapplied cash are double-counted as outstanding — reconcile to the GL AR control total before reporting. Disputed invoices should be tagged, not silently aged. This skill diagnoses and recommends; dunning emails, credit holds, and write-offs are irreversible or customer-facing and must be approved by the credit owner. Do not use it for a single-customer balance lookup (a direct query is faster) or where the AR subledger is not yet reconciled for the period.
