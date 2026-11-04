---
name: third-party-risk-tiering
triggers:
  - tier our vendors
  - TPRM tiering
  - third party inherent risk scoring
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Tiers a portfolio of third-party vendors by inherent risk so that diligence depth and reassessment cadence scale to exposure. Scores each vendor across the dimensions that drive inherent risk (data sensitivity accessed, system criticality, spend, regulatory scope, fourth-party/subprocessor reach, business continuity dependence) and assigns a tier (e.g. Critical/High/Medium/Low). Produces a ranked tiering table the TPRM team uses to route onboarding and monitoring.

# Steps

1. Confirm the tiering model: get the organization's existing inherent-risk criteria and tier thresholds via knowledge_search. If a policy exists, use its dimensions and weights verbatim; if none exists, propose a model and flag it as "proposed — needs TPRM sign-off" rather than presenting it as established.
2. Pull the vendor inventory with sql_query: vendor name, service description, data classification accessed, system/process criticality, annual spend, contract status, and any subprocessors. Note row count and any vendors missing key fields — incomplete records cannot be tiered confidently and must be listed as "data-incomplete", not defaulted to Low.
3. Score each vendor on every dimension against the agreed scale, compute the composite, and map to a tier per the thresholds. Keep the per-dimension scores visible so the tier is auditable; do not collapse to a single opaque number.
4. Write the tiering table sorted by composite descending, with the score breakdown, assigned tier, and implied diligence/reassessment cadence per tier. Report the data-incomplete and newly-Critical vendors as a separate callout. State that tier assignments are recommendations the TPRM owner ratifies; reassessment cadence changes for live vendors are staged, not auto-applied.

# Notes

The output is wrong if a vendor with no usable data is silently scored Low, if weights deviate from policy without flagging it, or if the composite hides the dimension scores so a reviewer can't challenge a tier. A vendor accessing regulated/sensitive data should never land below the policy's data-driven floor regardless of spend — check that floor. Mark any field sourced from a stale inventory as unverified. This is a draft tiering for human ratification; do not trigger onboarding gates, contract changes, or offboarding off it. Do not use when the question is residual (post-control) risk — this skill scores inherent risk only.
