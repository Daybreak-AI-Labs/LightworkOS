---
name: supplier-risk-assessment
triggers:
  - assess supplier risk
  - supply chain risk for this vendor
  - single source exposure
tools_needed:
  - web_search
  - spreadsheet
---
# What this skill does

Assesses supply-chain risk for a named supplier or a sourcing category, producing a scored risk assessment that quantifies exposure (spend, single/sole-source dependency, geographic and financial concentration) and pairs each material risk with a concrete mitigation. Handles vendor onboarding due diligence, annual supplier reviews, and rapid triage after a disruption signal.

# Steps

1. Establish the subject and the exposure base from real inputs: supplier name(s), annual spend, parts/categories sourced, and whether each is single-, sole-, or multi-sourced. If spend or sourcing status is unavailable, mark those fields unverified rather than estimating.
2. Gather external risk signals via web_search across the standard dimensions — financial health (credit/insolvency news), geographic and geopolitical exposure of the manufacturing site, regulatory/compliance flags, and recent disruption events. Cite each source with date; treat undated or single-source claims as unverified.
3. In a spreadsheet, score each dimension (e.g. 1-5 likelihood x impact) weighted by exposure, and compute an overall risk tier. Concentration matters: a single-source, high-spend, single-geography part dominates the score even with a healthy supplier.
4. Report the assessment as a ranked risk register: tier, the exposure drivers behind it, and a specific mitigation per material risk (qualify a second source, buffer stock, contractual terms, audit). State assumptions and data gaps; recommend actions for a human sourcing owner to approve — do not initiate supplier changes.

# Notes

The output is wrong if it scores the supplier's intrinsic health while ignoring exposure — a perfectly stable sole-source vendor is still high risk because there is no fallback. Mitigations must be specific and actionable, not generic ("monitor closely" is not a mitigation). External signals age fast; cite dates and flag stale or thin sourcing. Do not use this as a substitute for a formal financial-audit or legal sanctions screen, and never trigger contract or sourcing actions — those are staged recommendations for a human decision-maker.
