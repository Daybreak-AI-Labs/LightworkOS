---
name: meddic-deal-qualification
triggers:
  - qualify this deal
  - run MEDDIC on the opportunity
  - sales qualification scorecard
tools_needed:
  - knowledge_search
---
# What this skill does

Qualifies a B2B sales opportunity using the MEDDICC framework (Metrics, Economic buyer, Decision criteria, Decision process, Identify pain, Champion, Competition). Produces a scored qualification card that exposes which elements are known versus assumed, the biggest gaps threatening the deal, and concrete next steps to advance or disqualify. Output informs forecasting and deal strategy; it does not commit a forecast.

# Steps

1. Pull the opportunity record and all activity via `knowledge_search` (CRM notes, call recaps, emails, stakeholder map, stage, amount, close date). Anchor every conclusion to a real artifact — do not invent a champion or a metric that no source supports.
2. Populate each MEDDICC element from the evidence: quantified Metrics/business case, the named Economic buyer, documented Decision criteria and process, the Identified pain, a confirmed Champion (with a test of their influence), and Competition. Mark each element Known / Weak / Unknown with the source.
3. Score the deal (e.g. 0-2 per element) and compute an overall qualification level. Call out the gaps that most threaten the deal — a missing economic buyer or unconfirmed champion outweighs minor gaps — and note any single-threaded risk.
4. Recommend the next best actions per gap (specific questions to ask, stakeholders to reach, evidence to obtain) and a qualify/disqualify lean. Report the scorecard, state which elements are assumed vs. confirmed, and hand off to the account owner for the commit/strategy decision.

# Notes

The output is wrong if an element is marked Known without a cited interaction, if a "champion" is asserted who has never been tested for influence, or if the score is inflated to keep a deal alive. CRM data is often stale or optimistic — mark unconfirmed claims and date them. This is a qualification aid and recommendation only: forecast commits, discounting, and disqualifying a deal are human rep/manager decisions. Do not use as a closed-won predictor or to set quota.
