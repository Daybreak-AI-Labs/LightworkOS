---
name: project-roi-business-case
triggers:
  - project roi
  - business case
  - investment justification
  - should we fund this project
tools_needed:
  - spreadsheet
---
# What this skill does

Builds the financial business case for a proposed project or investment. Produces an ROI model with a costed buildout, quantified benefits, a multi-year cash-flow projection, and decision metrics (NPV, IRR, payback) plus a risk/sensitivity view — enough for a funding decision.

# Steps

1. Gather the inputs from the requester and source documents: one-time and recurring costs (capex, implementation, licenses, headcount, run-rate), the benefit thesis (revenue uplift, cost savings, risk avoidance) with the quantity-and-rate logic behind each, the time horizon, and the discount rate / hurdle rate. Mark any number that is an estimate vs sourced; never invent benefit figures.
2. In the spreadsheet, lay out a year-by-year cash flow: costs negative, benefits positive, net cash flow per period. Apply ramp/adoption curves to benefits rather than assuming day-one full run-rate. Keep every driver in a labeled assumptions block so reviewers can change one cell.
3. Compute NPV at the stated discount rate, IRR, and payback period; compare against the hurdle rate. Run sensitivity on the 2-3 swing assumptions (benefit realization %, cost overrun, timing) and show a downside/base/upside range, not a single point.
4. Report the recommendation with the decision metrics, the key assumptions and their sources, the sensitivity range, and the top risks with mitigations. State explicitly which benefits are committed vs aspirational. The funding decision is a human's; present the case, do not approve spend.

# Notes

The case is wrong if benefits are double-counted, booked at full run-rate from day one, or stated without a quantity x rate basis — these inflate NPV and are the most common failure. A discount rate or horizon pulled from nowhere invalidates NPV/IRR; confirm both. IRR is unreliable with sign-flipping cash flows — lean on NPV when that happens. Do not use for sunk-cost / already-committed spend, or as a substitute for the operational plan. Do not present aspirational benefits as committed; funding is an irreversible commitment decided by a human.
