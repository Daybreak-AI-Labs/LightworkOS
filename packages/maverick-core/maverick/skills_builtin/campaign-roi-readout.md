---
name: campaign-roi-readout
triggers:
  - campaign roi
  - campaign readout
  - what was our roas on that campaign
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Evaluates a completed or in-flight marketing campaign's financial return and produces a campaign readout: a full-funnel view (impressions through closed revenue), customer acquisition cost (CAC), return on ad spend (ROAS), and concrete learnings to carry into the next campaign. Produces a decision-ready memo, not a raw metric dump.

# Steps

1. Pin the campaign scope first: campaign ID(s), the exact start/end dates, the spend source of truth, and the attribution window/model in use. Do not proceed on a guessed date range — confirm it, because it sets the denominator for every metric.
2. Pull the funnel with `sql_query`: impressions, clicks, leads/signups, qualified opportunities, and closed-won revenue, each scoped to the campaign and attribution window. Pull spend from the authoritative ad/finance table, not an estimate. Record row counts and any nulls.
3. Compute in `spreadsheet`: step-to-step conversion rates, CAC (spend / new customers), ROAS (attributed revenue / spend), and blended vs. paid-only where the data supports it. Flag any metric resting on <30 conversions as low-confidence.
4. Write the readout: funnel table, CAC, ROAS, top 2-3 learnings (what to scale, cut, or test), and an explicit attribution-model caveat. Hand off stating the date range, attribution model, and any data gaps as assumptions; recommend next actions but leave budget reallocation for a human to approve.

# Notes

Wrong output usually traces to a mismatched attribution window between spend and revenue, double-counting from overlapping campaigns, or treating last-touch revenue as incremental (it rarely is — say so). ROAS without an attribution caveat is misleading; always state the model. Mark any figure not sourced from a system of record as unverified. This skill recommends — it does not pause spend, shift budget, or kill campaigns; those are human calls. Do not use it for brand/awareness campaigns with no revenue tie; use a reach/lift readout instead.
