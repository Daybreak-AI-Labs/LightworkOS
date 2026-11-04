---
name: business-case-builder
triggers:
  - build a business case for this investment
  - justify the investment to leadership
  - run the cost benefit analysis
tools_needed:
  - spreadsheet
  - knowledge_search
---
# What this skill does

Builds a decision-ready business case that justifies an investment to budget owners and executives. Produces a structured document plus a backing model: itemized costs, quantified benefits, NPV/payback over a defined horizon, sensitivity on the key drivers, and a risk register — so a sponsor can approve, defer, or reject with eyes open.

# Steps

1. Establish the decision frame: the problem, the proposed investment, the time horizon, the discount rate, and the do-nothing baseline. Pull comparable cost/benefit figures via `knowledge_search`; cite each source.
2. Build the cost side in `spreadsheet` — one-time (capex, implementation, migration) and recurring (licensing, headcount, opex) by year. Tag every figure as quoted, estimated, or assumed.
3. Quantify benefits the same way (hard savings, revenue, avoided cost, productivity); keep soft/strategic benefits in a separate qualitative section so they don't inflate the number.
4. Compute NPV, payback period, and ROI from the cash flows; run sensitivity on the 2-3 drivers that move the result most, and log risks with likelihood/impact/mitigation.
5. Report the recommendation with the headline numbers, the sensitivity range, and an explicit list of assumptions; flag that the model is a recommendation — the funding decision is the sponsor's.

# Notes

The case is wrong if benefits are double-counted, costs omit ongoing opex, or a single optimistic assumption drives the whole NPV — show the downside case, not just the base case. Never fabricate vendor quotes, adoption rates, or savings; mark every unsourced input as an assumption and make them easy to challenge. This is a draft to inform a human funding decision, not an approval. Don't use it for trivial spend below an approval threshold, or where the driver is regulatory/mandatory (frame as compliance, not ROI).
