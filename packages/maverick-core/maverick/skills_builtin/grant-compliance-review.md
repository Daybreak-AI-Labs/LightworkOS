---
name: grant-compliance-review
triggers:
  - review grant compliance
  - check allowable costs
  - prepare for a grant audit
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

Reviews spending and reporting against a grant's terms to surface compliance risk before a funder or auditor does. Produces a compliance review covering allowable-cost testing, budget-vs-actual, match/cost-share, and reporting-deadline status, with findings ranked by severity. Handles federal (e.g., Uniform Guidance / 2 CFR 200), foundation, and government grant agreements.

# Steps

1. Pull the grant agreement and rules from `knowledge_search`: budget, period of performance, allowable-cost basis, indirect rate, match requirement, reporting schedule, and any program-specific terms. Note the governing framework (Uniform Guidance vs. funder-specific).
2. Load the expenditure ledger into a `spreadsheet` and reconcile its total to the general ledger / drawdowns. An unreconciled ledger invalidates the whole review.
3. Test each cost against allowability (necessary, reasonable, allocable, within period, not on an unallowable list), and check the indirect rate is applied correctly. Flag charges lacking documentation rather than assuming they're clean.
4. Run budget-vs-actual by line, verify match/cost-share is met and properly sourced, and confirm every required report's status against its deadline.
5. Report findings ranked by severity (questioned costs, deadline misses, documentation gaps) with the cited rule for each, the dollar exposure, and a corrective action. State assumptions and reconciliation caveats; route to the grants manager.

# Notes

Output is wrong if costs aren't tested against the actual agreement terms, if the ledger wasn't reconciled, or if a finding lacks a citable rule and dollar amount. Cite the agreement clause or regulation behind each finding; mark undocumented charges as unverified, not as violations. This is a review, not an adjudication — disallowing a cost, returning funds, or amending a federal report are decisions for the grants manager/finance and possibly the funder. Do not use for proposal budgeting or for general financial-statement audits.
