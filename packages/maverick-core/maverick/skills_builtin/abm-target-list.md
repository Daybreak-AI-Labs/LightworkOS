---
name: abm-target-list
triggers:
  - abm
  - target account list
  - account selection for outbound
tools_needed:
  - sql_query
  - web_search
---
# What this skill does

Builds a scored target-account list for account-based marketing: candidate accounts pulled from CRM/data, scored against an ideal-customer-profile (ICP) fit and intent model, sorted into tiers (1/2/3), each with a suggested entry point (named persona or trigger event). Produces a ranked, actionable list ready for outbound and ad targeting.

# Steps

1. Define the ICP and scoring rubric before pulling anything: firmographic filters (industry, size, geo, tech stack), the fit weights, and what counts as an intent signal. Confirm the weights with the requester — an unstated rubric makes the ranking unauditable.
2. Pull the candidate universe with `sql_query` from CRM/data warehouse, excluding existing customers, open opps, and disqualified accounts. Capture the firmographic fields the rubric needs; log how many candidates dropped at each filter.
3. Enrich and validate the top candidates with `web_search` for current signals (funding, hiring, leadership change, product launch) and to confirm the account still exists and matches the profile. Cite each signal's source; mark accounts you could not verify as low-confidence rather than scoring them high.
4. Score, tier (Tier 1 = highest fit + intent), and attach a suggested entry point per account — the persona to reach and the trigger to lead with. Hand off the ranked list with the rubric and weights stated, flagging which enrichment signals are unverified and which accounts need human review before outreach.

# Notes

The list is wrong when stale firmographics inflate scores, when intent signals are scraped without a source, or when existing customers/active opps leak in and trigger duplicate outreach. Never fabricate a funding round or headcount to justify a tier — cite or mark unverified. This skill recommends a list; it does not launch sequences, buy ads, or contact anyone — a human approves the final accounts and any outreach. Do not use it for broad lead-gen or inbound scoring; ABM assumes a finite, deliberately chosen set.
