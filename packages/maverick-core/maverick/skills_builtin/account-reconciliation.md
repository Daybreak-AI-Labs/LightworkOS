---
name: account-reconciliation
triggers:
  - account reconciliation
  - gl recon
  - tie out
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Reconciles a single general-ledger account balance to its independent support (subledger detail, bank statement, schedule, or third-party confirmation) for a given period, identifying and explaining every difference. Output is a reconciliation showing the GL balance, the supported balance, the reconciling items with explanations, and an aging of any open differences.

# Steps

1. Confirm the target account, entity, and period-end date. Pull the GL ending balance with sql_query (account, period, entity filter) and capture the as-of timestamp. Identify the authoritative support for this account type — subledger detail, bank statement, amortization/lease schedule, or confirmation — and load it via spreadsheet or sql_query.
2. Match support to GL at the transaction or balance level. Compute the raw difference (GL balance minus supported balance) and itemize every reconciling component: timing items (in-transit, unposted), known accruals, errors, and unexplained residual. Never force the difference to zero by inventing a plug.
3. Age the open reconciling items by the date they originated (0-30 / 31-60 / 61-90 / 90+ days) and flag aged or unexplained items above the materiality threshold for follow-up. For each reconciling item, attach the source reference (transaction id, statement line, schedule row) so it is traceable.
4. Report the reconciliation: GL balance, supported balance, total reconciling items, residual unexplained difference, and the aging. State assumptions (cutoff date, FX, materiality threshold used) and recommend correcting entries for explained errors — but stage any GL adjustment for a human preparer/reviewer to post. Mark unverified items explicitly.

# Notes

The reconciliation is wrong if the residual is plugged to zero, if a reconciling item lacks a source reference, or if support and GL are pulled as of different cutoff dates. Aged unexplained differences are the real signal — surface them, do not bury them. Recommend journal entries; do not post them — posting is the human's irreversible action. Cite the GL query and the support document for every number; mark anything you could not tie as unverified. Do not use this to explain period-over-period movement (use flux-analysis) or to run the full close (use month-end-close-checklist).
