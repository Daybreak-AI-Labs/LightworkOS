---
name: insurance-program-review
triggers:
  - insurance program review
  - coverage review
  - policy renewal
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

Reviews the corporate insurance program across all lines (property, general/product liability, D&O, cyber, E&O, workers' comp, business interruption, etc.) against the firm's risk profile and contractual obligations. Produces a review summarizing limits, deductibles, premiums, and renewal dates and identifying coverage gaps, overlaps, and underinsured exposures.

# Steps

1. Retrieve current policy documents and the schedule of insurance from the knowledge base with `knowledge_search` (carrier, line, limit, sublimits, deductible/retention, premium, policy period, key exclusions). Cite each policy source; flag any line for which no document is found.
2. Identify the firm's material exposures (asset values, headcount, revenue, data/PII footprint, contractual insurance requirements from key contracts/leases/loan covenants). Source each requirement and mark anything inferred as `unverified`.
3. Map exposures to coverage in `spreadsheet`: for each risk, record whether it is covered, the limit vs. estimated maximum loss, the retention, and notable exclusions. Compute total cost of risk and flag upcoming renewals within the window.
4. Produce the review: a coverage matrix plus a prioritized list of gaps (uncovered risks), overlaps (duplicate coverage), underinsured limits, and any contractual non-compliance. Report findings with recommendations (increase limit, add line, renegotiate) as recommendations only; state assumptions and hand off to the risk manager / broker. Binding or canceling coverage is out of scope.

# Notes

Wrong if exclusions and sublimits are ignored (a policy can name a peril yet exclude the actual loss), if contractual insurance requirements are missed (a breach can void a lease or loan), or if limits are judged without an exposure estimate. Always cite the policy document and date; never assert coverage from memory. This skill recommends — it does not bind, cancel, or alter policies; a human and licensed broker decide. Not for individual claims adjudication or actuarial pricing.
