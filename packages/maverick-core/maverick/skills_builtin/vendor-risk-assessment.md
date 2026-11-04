---
name: vendor-risk-assessment
triggers:
  - assess this vendor's risk
  - third party risk assessment
  - run tprm on this supplier before onboarding
tools_needed:
  - knowledge_search
  - web_search
---
# What this skill does

Produces a third-party (TPRM) risk assessment for a vendor being onboarded, covering security, privacy, financial, compliance, and concentration risk. It assigns a risk tier driven by the data and access the vendor will hold and enumerates the controls and contract clauses required before go-live. Output is a recommended assessment and gating decision draft — final approval stays with risk/procurement owners.

# Steps

1. Establish the engagement facts: vendor legal name, the service, what data they will process (categories, volume, special categories), the access/integration they get (network, prod, admin, sub-processing), and criticality to operations. Missing inheritance here invalidates the tier, so state assumptions if the intake is thin.
2. Use `knowledge_search` for internal signals first: prior assessments of this vendor, existing security questionnaires/SOC 2 or ISO 27001 reports on file, DPA status, and any incident history. Then use `web_search` for external signals — breach history, regulatory actions, financial-distress or ownership-change news, and certification validity — citing each source and dating it; mark anything not from a primary/authoritative source as "unverified".
3. Score the standard domains (security posture, privacy/data protection, compliance/certifications, financial stability, operational/concentration, fourth-party/sub-processors). Derive the risk tier primarily from data sensitivity × access × criticality, not from the questionnaire score alone.
4. Map each material gap to a required control or contract clause (e.g. encryption, breach-notification SLA, audit rights, sub-processor approval, exit/data-return) and produce: the tier, the findings table with sources, the required-controls list, and a recommended onboarding decision (approve / approve-with-conditions / reject). Report assumptions and hand the gating decision to the risk owner.

# Notes

The assessment is wrong if the tier is read off a self-attested questionnaire without corroboration, if a stale or out-of-scope SOC 2 is accepted as current, or if sub-processors (fourth-party risk) are ignored. Common failure modes: trusting vendor marketing claims as verified, missing that a "low data" tool actually gets prod access, and skipping financial/concentration risk for a single-source critical vendor. Never issue the final approval or sign the contract — recommend and stage conditions for the risk/procurement owner. Do not use this for a full security audit or pen test; it is a pre-onboarding risk screen.
