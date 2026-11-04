---
name: underwriting-risk-assessment
triggers:
  - underwriting assessment
  - risk appetite check
  - uw risk review
tools_needed:
  - knowledge_search
---
# What this skill does

Assesses a submitted risk against the carrier's underwriting appetite and guidelines, producing an accept / decline / refer-with-conditions recommendation. It scores the risk on appetite fit, exposure characteristics, and pricing adequacy, and cites the guideline that drives each conclusion.

# Steps

1. Extract the risk's key attributes from the submission (class/SIC, geography, limits/deductible, exposure base, loss history, occupancy/operations, requested coverages). Note any missing underwriting information explicitly rather than assuming it.
2. Search the underwriting appetite guide and guidelines (knowledge_search) for the matching class: in-appetite / restricted / prohibited status, required referral triggers, line-size and capacity limits, and mandatory exclusions or conditions for that class.
3. Evaluate fit and adequacy: compare attributes to appetite (in/out and why), assess loss history against expected, and check that the proposed price/terms clear pricing adequacy or referral thresholds. Flag any prohibited or referral-trigger condition.
4. Produce the assessment: recommendation (accept / decline / refer), appetite-fit rationale with cited guideline sections, pricing-adequacy note, and required conditions/exclusions. State assumptions and missing data; stage binding authority decisions for an authorized underwriter.

# Notes

Wrong when class mapping is incorrect, a referral trigger or prohibited-class rule is missed, or an unverified submission detail is treated as fact. Always cite the specific guideline; mark anything not found in the knowledge base as unverified rather than guessing appetite. This recommends only — bind/quote/decline with authority, and any deviation from guidelines, are human underwriter decisions. Do not use to set portfolio rate level (that is actuarial pricing).
