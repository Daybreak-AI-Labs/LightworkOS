---
name: ltv-cac-analysis
triggers:
  - ltv cac
  - unit economics
  - customer lifetime value
tools_needed:
  - sql_query
  - spreadsheet
---

# What this skill does

Computes customer lifetime value, acquisition cost, and the LTV:CAC ratio and payback — the unit economics that say whether growth spend is healthy.

# Steps

1. Define cohorts and the LTV basis (gross-margin LTV, not revenue) and pull retention/revenue curves with `sql_query`. Decide the horizon and discount rate.
2. Compute CAC fully loaded (sales + marketing, including salaries) by cohort/channel, not just media spend, in `spreadsheet`.
3. Derive LTV:CAC and CAC payback months by segment/channel; show the curve and the assumptions that move it most.
4. Flag channels below the healthy bar and where retention (not CAC) is the lever. State assumptions and hand off.

# Notes

The classic errors: revenue-LTV instead of margin-LTV, CAC excluding salaries, and a blended ratio hiding a bad channel. Segment it. Budget reallocation is the operator's decision; this skill provides the economics.
