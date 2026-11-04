---
name: deal-desk-review
triggers:
  - deal desk review
  - deal review
  - non standard deal
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

Reviews a single non-standard deal (custom pricing, terms, or scope) against current deal-desk policy and produces a structured review listing every clause that deviates from standard, the policy citation it triggers, and the named approval level required. Output is a recommendation, not an approval — it stages exceptions for the correct human approver.

# Steps

1. Load the deal record into the spreadsheet tool: line items, list price, quoted price, discount %, payment terms, contract length, non-standard clauses (uplift caps, custom SLAs, MFN, termination for convenience). Note any field missing rather than inferring it.
2. Pull the governing policy with knowledge_search (discount approval matrix, term-and-condition standards, margin floor) and cite the exact policy version/section returned; if no policy matches a clause, mark it "no policy found — escalate."
3. For each line and clause, compute the deviation (discount vs. matrix threshold, term vs. standard, margin vs. floor) and map it to the approval tier (e.g., rep, manager, VP, CFO) named in the policy.
4. Report a table of deviations with policy citation, magnitude, and required approver; summarize the highest approval tier triggered and flag unresolved/no-policy items. State assumptions (e.g., list price source) and hand off to the deal-desk approver — do not mark the deal approved.

# Notes

The review is wrong if a deviation is measured against a stale policy version (always cite the version) or if a missing field is silently treated as compliant — surface gaps explicitly. This skill only drafts and recommends; granting the exception is an irreversible commercial commitment reserved for the human approver in the matrix. Do not use it for standard, fully in-policy deals (no deal-desk review needed) or for renewals priced at standard terms.
