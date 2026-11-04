---
name: renewal-risk-assessment
triggers:
  - is this renewal at risk
  - assess churn risk for the account
  - score this account's renewal
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Assesses churn risk for an upcoming renewal and produces a risk rating with the specific drivers behind it and a concrete save plan. Combines hard usage/support/commercial signals with qualitative account context so the CSM gets an actionable, evidence-backed read — not a vibe.

# Steps

1. Confirm the target account and renewal date. Pull quantitative signals via `sql_query`: product usage/adoption trend, license utilization, support ticket volume/severity, NPS/CSAT, payment history, and days-to-renewal.
2. Run `knowledge_search` over account notes, QBRs, and recent threads for qualitative signals: exec sponsor changes, stated dissatisfaction, competitor mentions, open escalations.
3. Score risk (e.g. Low/Medium/High) and rank the drivers by contribution; cite the underlying metric or source for each driver so it can be verified.
4. Produce a save plan: per-driver mitigation, owner, and timing relative to the renewal date. Hand off to the CSM/manager, flagging any signals you could not source and stating the assumptions in the score.

# Notes

Wrong if the score is asserted without the per-driver evidence, if stale data is treated as current (always note the data window), or if qualitative signals are guessed rather than retrieved. Discounts, exec escalations, and contract concessions are recommendations only — a human approves them. Don't use for closed/churned accounts or for net-new pipeline.
