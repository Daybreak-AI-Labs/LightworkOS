---
name: icp-definition
triggers:
  - define our ICP
  - ideal customer profile
  - who is our target customer
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Defines or refines the Ideal Customer Profile by grounding it in actual customer outcomes rather than aspiration. Produces an ICP specification with firmographic and behavioral criteria, the signals that predict a good fit, and explicit exclusion (anti-) criteria, all backed by data from the existing book of business. Output guides targeting and prioritization; it is a recommendation for revenue leadership to ratify.

# Steps

1. Define "good customer" measurably (high retention, expansion, short sales cycle, high margin, low support load) and pull the cohort from the warehouse via `sql_query` — segment best accounts vs. churned/poor-fit accounts. Capture the SQL and row counts so the basis is auditable.
2. Compare the two cohorts across firmographic dimensions (industry, employee count, revenue band, geography, tech stack, growth stage) and behavioral signals (activation, usage depth, buying triggers). Identify the attributes that actually separate winners from losers; cite the query result behind each — do not assert a criterion the data does not support.
3. Enrich with qualitative context from `knowledge_search` (win/loss notes, CS feedback, sales objections) to explain *why* a pattern holds. Draft the ICP: inclusion criteria, predictive fit signals, and explicit exclusions / disqualifiers (segments that consistently churn or never convert).
4. Report the ICP spec with the supporting data per criterion, distinguish data-backed criteria from hypotheses needing validation, state cohort/time-window assumptions, and hand off to RevOps / GTM leadership to ratify before it drives targeting or scoring.

# Notes

The output is wrong if a criterion has no cohort evidence, if the "good customer" definition is undocumented or cherry-picked, or if exclusions are omitted (a vague ICP that matches everyone is useless). Small or skewed cohorts produce spurious patterns — note sample sizes and time window, and mark thin segments as unverified hypotheses. This is a recommendation only: changing segmentation, lead scoring, or sales coverage are human GTM decisions. Do not use as a hard lead-rejection filter without leadership ratification and a validation period.
