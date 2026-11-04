---
name: population-health-stratification
triggers:
  - population health
  - risk stratification
  - rising risk
tools_needed:
  - sql_query
  - pandas_query
---
# What this skill does

Stratifies a member population into risk cohorts (e.g., high-risk, rising-risk, low-risk, healthy) using utilization, diagnosis, and risk-score signals, then maps each cohort to an appropriate intervention tier. Produces a reproducible cohort assignment plus a recommended intervention plan for care-management triage. Recommends; it does not enroll members or trigger interventions.

# Steps

1. Define the population and the stratification inputs available: the cohort denominator, the time window, and which signals exist (claims utilization, chronic-condition flags, risk scores such as HCC/ACG, ED/IP visits, pharmacy adherence). Confirm field definitions in the schema before using them.
2. Use `sql_query` to assemble a member-level feature table over the window. Then use `pandas_query` to compute the stratification — either a documented rule set (thresholds on the agreed signals) or score banding — and produce one cohort label per member. Keep the logic explicit and reproducible; do not invent thresholds without grounding them in clinical or actuarial guidance.
3. Validate the cut: report cohort sizes, the distribution of key drivers per cohort, and surface "rising-risk" members (moderate now, trending up) since they are the highest-yield intervention target. Sanity-check that high-risk counts are plausible, not an artifact of a missing exclusion.
4. Map cohorts to intervention tiers (complex care management, disease management, wellness/light-touch) with rationale, and report the cohort table plus the assignment logic. State assumptions (data completeness, attribution, look-back length) a human owner must confirm before operationalizing.

# Notes

Output is wrong if thresholds are arbitrary, if data gaps (e.g., new members with no claims history) get silently scored as low-risk, or if attribution assigns members to the wrong panel. Risk scores are signals, not destiny — never present a cohort label as a clinical diagnosis. This skill triages and recommends; enrollment into a care-management program is a human decision. Member-level outputs are PHI and stay in the governed environment. Not for individual care planning — this is population-level segmentation.
