---
name: engagement-survey-action
triggers:
  - engagement action
  - survey action plan
  - turn survey results into action
  - engagement drivers
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Converts raw engagement-survey results into a prioritized action plan tied to the specific drivers moving the score, with named owners and a follow-up cadence. Handles the goal class "we ran a survey, now what do we DO about it" and produces an evidence-backed plan, not a slide of generic platitudes.

# Steps

1. Pull the survey result set with `sql_query` from the survey/HRIS tables: overall favorability, per-driver scores, response rate, and prior-period values for trend. Segment by org unit, tenure, and manager where the data supports it; flag any segment with n below the confidentiality threshold (commonly n<5) and exclude it from breakdowns.
2. Rank drivers by impact, not just by low score: correlate each driver against the outcome item (intent-to-stay / overall engagement) if the linked data exists; otherwise rank by the largest unfavorable gap versus benchmark or prior period. Mark which ranking method you used.
3. For the top 3-5 priority drivers, use `knowledge_search` to retrieve known interventions and any prior action plans for similar drivers; cite the source for each recommended action and mark anything not grounded in the data or knowledge base as "unverified hypothesis."
4. Assemble the action plan: per driver, list 1-3 concrete actions, a proposed owner (role/manager from the org data — do not invent names), a target date, and a measure of done. End by reporting the plan with stated assumptions (response rate, segments suppressed, ranking method) and hand off to HRBP/leadership for owner confirmation.

# Notes

Wrong if it treats the lowest-scoring item as the top priority without checking impact, or if it surfaces a segment below the privacy threshold (re-identification risk). Low response rate makes everything provisional — say so. The skill DRAFTS and RECOMMENDS; assigning owners, committing budget, or communicating results to staff are irreversible org actions staged for a human leader to approve. Do not use for individual performance management — survey data is aggregate and confidential by design.
