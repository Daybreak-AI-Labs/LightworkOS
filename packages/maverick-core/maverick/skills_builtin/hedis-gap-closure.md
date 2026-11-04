---
name: hedis-gap-closure
triggers:
  - hedis
  - quality gaps
  - care gaps
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Produces a HEDIS/quality-gap closure plan for a defined measure and population: which members have open gaps, why, and a prioritized outreach plan to close them before the measurement-year deadline. Outputs a member-level gap list plus a tracking framework (channel, owner, status). Recommends actions; it does not contact members or alter records.

# Steps

1. Fix the measure and denominator: the HEDIS measure (e.g., CBP, HbA1c control, breast cancer screening), measurement year, and the eligible population. Use `knowledge_search` to load the current-year measure specification (numerator/denominator/exclusions) and cite its version — specs change yearly and a stale spec mislabels gaps.
2. Use `sql_query` against the member/claims/lab data to compute, per member, denominator eligibility, numerator-met status, valid exclusions, and supplemental-data hits. Report the query and row counts; do not assume a field's meaning without confirming it in the schema.
3. Stratify open gaps by closeability and impact: members one action from compliant, those needing a visit/lab, and those likely excludable (pending chart review). Prioritize by deadline proximity and measure weight.
4. Draft the outreach plan — channel (call, text, mailer, provider tasking), owner, and cadence — plus a tracking table (member, gap, action, status, close date). Report the gap list and plan, and state assumptions (e.g., claims lag, supplemental-data completeness) a human must validate before launch.

# Notes

The plan is wrong if the measure spec is from the wrong year, if exclusions are ignored (inflating the gap list and burning outreach on compliant members), or if claims runout lag makes "open" gaps already closed. Member-level data is PHI — keep it within the governed environment and never expose identifiers in summaries. This skill stages outreach for human approval; it must not auto-send communications or write back to the quality system. Not for ad-hoc single-member lookups — use a direct query for that.
