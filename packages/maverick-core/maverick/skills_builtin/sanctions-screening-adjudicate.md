---
name: sanctions-screening-adjudicate
triggers:
  - sanctions hit
  - ofac match
  - screening adjudication
tools_needed:
  - knowledge_search
  - web_search
---
# What this skill does

Adjudicates a single sanctions/watchlist screening alert: compares the screened party against the matched list entry, determines whether it is a true match or a false positive, and documents the reasoning. Produces an audit-ready adjudication memo that a compliance officer reviews before clearing or escalating. Handles the recurring alert-triage task at the core of sanctions compliance.

# Steps

1. Pull both sides of the alert: the screened party's identifiers (full name, DOB, address, nationality, entity type, ID numbers) and the matched list entry (program, e.g. OFAC SDN/EU/UN/HMT, plus all listed aliases, DOB, locations, IDs). If a screened identifier is missing, record it as a data gap — do not assume a value.
2. Use `knowledge_search` against KYC/onboarding records and prior dispositions to corroborate the customer's true identity; use `web_search` only to confirm the current authoritative list entry and effective date. Cite the source and as-of date for every list fact; mark anything unconfirmed as unverified.
3. Compare discriminating fields (DOB, nationality, ID numbers, address, entity vs individual). Score the match: secondary-identifier mismatches support false positive; concordance across strong identifiers supports true match. State which fields drove the decision and note any 50%-rule ownership exposure for entities.
4. Draft the adjudication memo: alert ID, parties, fields compared, disposition (false positive / potential true match — escalate), rationale, sources with dates, and residual gaps. Report the recommendation and hand off to a compliance officer for sign-off.

# Notes

Output is wrong if it clears on a name-only match, ignores aliases, treats stale list data as current, or misses entity ownership exposure. Adjudication is a recommendation only: a designated compliance officer makes the clear/escalate/block decision and files any SAR/OFAC report — those irreversible actions are never auto-executed. Never fabricate a list entry or DOB; an unverifiable fact must be escalated, not cleared. Do not use to design screening rules, tune fuzzy-match thresholds, or batch-clear alerts — one alert per run.
