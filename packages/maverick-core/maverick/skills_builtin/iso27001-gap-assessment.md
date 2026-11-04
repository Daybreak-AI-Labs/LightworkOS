---
name: iso27001-gap-assessment
triggers:
  - iso 27001 gap
  - isms gap assessment
  - annex a controls review
tools_needed:
  - knowledge_search
---
# What this skill does

Assesses an organization's information security management system (ISMS) against ISO/IEC 27001:2022 Annex A controls, identifying implemented, partial, and missing controls. Produces a gap assessment table plus a draft Statement of Applicability (SoA) marking each control as applicable/excluded with justification and implementation status.

# Steps

1. Confirm scope with the requester: ISMS boundary (entities, sites, systems), the certification target (new cert vs surveillance), and whether the 2022 or legacy 2013 control set applies. Do not assume — record what is stated.
2. Pull the authoritative control list and clause text via knowledge_search (ISO/IEC 27001:2022 Annex A: 93 controls across 4 themes — Organizational, People, Physical, Technological). Cite the clause/control IDs you reference; mark any control you cannot ground as "unverified."
3. For each control, gather current-state evidence from supplied policies, prior audits, and knowledge_search over the org's documented practices. Rate each: Implemented / Partial / Missing / Not Applicable, with a one-line evidence pointer or "no evidence found."
4. Build the gap table (control ID, theme, status, evidence, gap, suggested remediation) and the draft SoA (applicable Y/N, justification, status). Report the count by status and top remediation priorities; hand off to a human owner, stating that exclusions and risk acceptances require sign-off.

# Notes

Output is wrong if controls are rated "Implemented" without evidence — absence of evidence is a gap, not a pass. Never fabricate clause numbers or evidence; mark unverified items explicitly. The SoA and any control exclusion are a draft recommendation only: a CISO or accountable owner must approve exclusions and accept residual risk. Do not use for a formal certification audit decision — this stages findings for a certified auditor, it does not replace one. Confirm the 2022 vs 2013 mapping before reusing legacy control numbers.
