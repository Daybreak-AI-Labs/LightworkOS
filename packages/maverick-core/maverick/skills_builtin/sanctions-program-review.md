---
name: sanctions-program-review
triggers:
  - sanctions program
  - ofac compliance
  - screening program
tools_needed:
  - knowledge_search
---
# What this skill does

Reviews an institution's sanctions-compliance program against the five OFAC framework pillars (management commitment, risk assessment, internal controls, testing/audit, training), with focus on the screening engine and program governance. Produces a structured review identifying control and governance gaps, each rated by exposure and mapped to a remediation recommendation, for the sanctions officer to action. Output is an assessment and recommendation, not a remediation that is self-applied.

# Steps

1. Establish the program baseline: collect the institution's sanctions risk profile (customer geographies, products, payment rails, correspondent relationships) and current program artifacts (policy, screening configuration, list-update cadence) from the case inputs and `knowledge_search`; cite the OFAC framework expectations you are measuring against so each finding is grounded.
2. Assess screening specifically — lists screened (OFAC SDN/consolidated and any applicable non-US lists), customer vs. real-time transaction screening coverage, fuzzy-matching/threshold configuration, list-update timeliness, and alert-disposition quality. Flag coverage gaps (e.g. a payment rail or list not screened) and tuning weaknesses; mark any control you could not evidence as UNVERIFIED rather than assuming it exists.
3. Assess governance and the remaining pillars — senior-management accountability, the documented and dated risk assessment, escalation/blocking-and-rejecting procedures, independent testing/audit cadence and findings closure, and role-based training. Note where a pillar is missing, stale, or undocumented.
4. Rate each gap by exposure (regulatory + likelihood of a missed match), map it to a concrete remediation, and rank. Hand the review to the sanctions officer stating assumptions, which controls are cited vs. UNVERIFIED, and that any screening reconfiguration or list change requires validation before production.

# Notes

Wrong if it credits a control without evidence — "assumed in place" is how real screening gaps survive audits, so anything unconfirmed is UNVERIFIED. Sanctions exposure is strict-liability and irreversible (a missed SDN match can mean a prohibited transaction); findings must be conservative and traceable to OFAC guidance via `knowledge_search`. This skill reviews and recommends only — applying screening-threshold changes, blocking decisions, or program edits is a human governance action requiring validation. Do not use it to clear a live screening alert or to make a blocking/rejection determination on a specific transaction.
