---
name: ap-payment-run-review
triggers:
  - payment run
  - ap batch
  - payment review
  - review payables before release
tools_needed:
  - sql_query
---
# What this skill does

Reviews a proposed accounts-payable payment run (batch) before it is released, flagging holds, exceptions, and policy violations against the source AP ledger. Produces a per-payment review table separating clean items from items requiring action, plus a release/no-release recommendation. The output is a control gate for a human approver — it never releases payments.

# Steps

1. Pull the proposed run from the AP system via sql_query: invoice ID, vendor, amount, currency, due date, payment method, bank/remit-to details, GL coding, and approval status. Confirm the run total reconciles to the batch header the user named; if they differ, stop and report the gap.
2. Run exception checks against the same ledger: duplicate invoice numbers or (vendor, amount, date) tuples; payments to vendors on hold/blocked or with missing/recently-changed bank details; amounts over approval thresholds lacking sign-off; one-time/new vendors; negative or zero amounts; invoices past due vs. early-paid (lost discount or pulled-forward cash).
3. Cross-check vendor master for changed remit-to/bank info within the lookback window (potential fraud signal) and for sanctions/blocked flags if those columns exist; mark any item you cannot verify as "unverified" rather than passing it.
4. Classify each payment as CLEAR, HOLD (block this item), or REVIEW (needs a decision), and report: run total, count and dollar value by classification, the exception detail rows, and a recommended action — stating assumptions (e.g., duplicate window, threshold values) and handing the release decision to the approver.

# Notes

Wrong outputs come from reconciling against the wrong batch, a too-narrow duplicate-detection window, or treating missing vendor-master fields as "clean." Bank-detail changes and new vendors are fraud-relevant — always surface them even when amounts are small. This is a recommend-only gate: stage holds and exceptions for a human; do not trigger, approve, or release any payment. Do not use for cash-flow forecasting or for post-payment reconciliation — it assumes an unreleased run.
