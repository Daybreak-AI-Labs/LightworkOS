---
name: customer-reference-program
triggers:
  - run a reference program
  - customer references
  - advocacy
  - find a referenceable customer
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Stands up and operates a customer-reference program: identifies referenceable accounts, matches them to inbound reference requests (by industry, use case, deal stage, region), and produces a recruitment plan to grow the advocate pool. Output is a ranked reference roster plus a matched shortlist for a named request and a recruitment list of likely-but-not-yet-enrolled advocates.

# Steps

1. Pull candidate accounts from the source of record: `sql_query` for accounts with health/NPS score, tenure, ARR, industry, region, product lines, and outcomes (e.g. documented ROI). Filter to active, non-churning, non-NDA-blocked accounts. Record the query and as-of date.
2. Score and rank referenceability: combine satisfaction signal (NPS promoter / high health), proven outcome, recency of value, and reference fatigue (cap recent reference activity per account — `sql_query` the reference-activity log). Flag any account missing consent or with legal/competitive sensitivity as ineligible until cleared.
3. Match to the request: take the request's criteria (target industry, use case, persona, deal stage, geo) and return the top N eligible accounts with the specific attributes that justify each match. Note gaps where no clean match exists.
4. Build the recruitment list from near-miss promoters not yet enrolled, with a suggested ask and channel per account. Hand off the roster, the matched shortlist, and the recruitment plan, stating consent assumptions and which accounts still need legal sign-off before being contacted.

# Notes

Output is wrong if it surfaces accounts without explicit reference consent, ignores reference fatigue (over-asking burns advocates), or matches on ARR/logo prestige instead of fit to the request. Consent status and competitive sensitivity are load-bearing — mark unverified consent explicitly; never auto-contact a customer. This skill drafts and recommends; a human (CSM/AE) approves and makes the actual outreach. Do not use for one-off "who can take a call tomorrow" panics where the source-of-record data is stale — verify currency first.
