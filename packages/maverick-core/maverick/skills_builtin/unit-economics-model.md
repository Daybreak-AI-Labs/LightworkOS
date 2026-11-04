---
name: unit-economics-model
triggers:
  - model our unit economics
  - calculate ltv and cac
  - what is our payback period
tools_needed:
  - spreadsheet
---
# What this skill does

Builds a per-unit profitability model for a business or product line: contribution margin, customer acquisition cost (CAC), lifetime value (LTV), the LTV:CAC ratio, and CAC payback period. Produces a transparent model where every input is sourced and every formula is auditable, so leadership can see whether each customer is profitable and how fast acquisition spend is recovered.

# Steps

1. Gather inputs from `spreadsheet` or provided financials: average revenue per unit/customer, gross margin %, churn rate (or retention/expected lifetime), total sales & marketing spend, and new customers acquired in the same period. Label each input with its source and time window; mark any input you had to assume as `ASSUMED` and do not bury it.
2. Compute CAC = S&M spend / new customers acquired over a matched period. Compute contribution margin per customer = revenue × gross margin %. Derive expected lifetime = 1/churn (for a given period), and LTV = contribution margin per period × expected lifetime (apply a discount rate only if cash-flow timing matters and state it).
3. Compute LTV:CAC ratio and CAC payback period = CAC / (contribution margin per period). Benchmark against common rules of thumb (LTV:CAC ≈ 3+, payback under ~12 months for SaaS) but flag these as heuristics, not targets for this specific business.
4. Assemble the model with inputs, formulas, and outputs visible, then report the LTV:CAC, payback, and the 2-3 inputs the result is most sensitive to (run a quick low/base/high on churn and CAC). State all assumptions and the period basis explicitly.

# Notes

Most errors come from mismatched periods (annual LTV vs monthly CAC), using revenue instead of contribution margin in LTV, or computing CAC on blended spend when only paid acquisition was intended — call out which you used. A high LTV:CAC built on an optimistic churn assumption is the classic trap; always show the churn sensitivity. The model is a decision aid, not a verdict: budget reallocations and pricing changes are recommendations a human approves. Do not use when cohorts are too young to estimate churn — say so and propose collecting more retention data first.
