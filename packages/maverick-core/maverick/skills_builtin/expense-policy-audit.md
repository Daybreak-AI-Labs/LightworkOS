---
name: expense-policy-audit
triggers:
  - expense audit
  - t&e audit
  - policy compliance
---
# What this skill does

Audits a set of expense or T&E transactions against the organization's written expense policy and flags exceptions. Produces an exception list where each flagged item cites the specific rule it violates and the amount at issue, ready for finance review.

# Steps

1. Load the expense policy thresholds and rules (per-category caps, receipt-required floor, approval tiers, blocked categories, per-diem limits, submission-window deadlines) from the policy source; capture rule IDs/section references for citation.
2. Pull the expense lines in scope via `sql_query` — amount, category, date, submitter, approver, receipt flag, and any project/cost-center tags.
3. Test each line against every applicable rule: over-cap amounts, missing receipts above the floor, wrong/insufficient approval tier, blocked or out-of-policy categories, duplicate submissions, and stale/late filings. Record the matched rule and the dollar exposure per exception.
4. Compile the exception list grouped by severity (hard violation vs needs-review), total the exposure, and hand off — stating the policy version/date used and noting any line where the policy is silent or ambiguous rather than forcing a verdict.

# Notes

Output is wrong if a flag cites no rule, if the policy version is stale (caps change — confirm the effective-dated policy), or if currency/tax handling inflates amounts. Duplicate detection is heuristic — mark suspected dupes as "review," not "confirmed." This is an audit draft that recommends; it does not reject reimbursements or claw back funds — a human approver decides. Don't use it where there is no written policy to test against; gather the policy first.
