---
name: ar-collections-strategy
triggers:
  - build a collections strategy
  - prioritize our receivables
  - set up a dunning plan
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Turns an open accounts-receivable ledger into a risk-ranked collections plan: which overdue accounts to pursue first, by how much, and with what action and cadence. Produces a prioritized account list with risk scores plus a dunning sequence (reminder, call, escalation, hold/legal) tied to dollars and aging. The output is a plan collectors and AR leadership execute.

# Steps

1. Pull open AR with sql_query: per-invoice balance, invoice and due dates, customer, payment terms, and available history (days-late trend, prior disputes, partial-payment behavior, credit limit). Confirm the as-of date and exclude credits/unapplied cash so the open balance is real.
2. In the spreadsheet build the aging buckets (current, 1-30, 31-60, 61-90, 90+) and a risk score per account from amount at risk, days past due, payment-history reliability, and dispute/credit flags. Concentrate the eye on high-balance, high-days, deteriorating-trend accounts.
3. Segment accounts into tiers and assign each a contact strategy and cadence: gentle reminders for low-risk current/early, structured dunning and calls for mid-tier, escalation to credit hold / payment plan / collections handoff for high-risk aged balances. Note any account near or over its credit limit.
4. Report the ranked account list with risk score, recommended action, owner, and next-contact date, plus total dollars addressed per tier and expected sequencing. Draft any customer-facing dunning messages as drafts; state assumptions and route credit holds, write-offs, and legal referral to a human for approval.

# Notes

The plan is wrong if aging is computed from invoice date instead of due date, if unapplied cash/credit memos inflate the open balance, or if risk ranks on raw balance while ignoring days-late and history. Disputed invoices need resolution routing, not dunning — separate them. Any external communication must be a draft pending review; never auto-send to customers. Credit holds, write-offs, and legal escalation are irreversible relationship/financial actions decided by AR/credit management, not the agent — this skill prioritizes and recommends, it does not enforce.
