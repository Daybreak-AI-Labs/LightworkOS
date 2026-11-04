---
name: gap-assessment-framework
triggers:
  - run a gap assessment
  - SOC 2 readiness
  - where are our control gaps
tools_needed:
  - knowledge_search
---
# What this skill does

Measures an organization's current control posture against a named standard or framework (SOC 2, ISO 27001, NIST CSF/800-53, PCI DSS) and identifies the delta. Produces a control-by-control gap assessment with a maturity score per control, evidence gaps, and a prioritized remediation roadmap. Output is an internal readiness draft, not an attestation or certification.

# Steps

1. Confirm the exact framework, version, and scope (which Trust Services Criteria, which ISO Annex A controls, which NIST profile/baseline). Pull the authoritative control list via `knowledge_search`; if the version is ambiguous, state which one you assumed and proceed.
2. For each control, retrieve current-state evidence from internal knowledge (policies, prior audits, system configs, tickets) via `knowledge_search`. Map each control to its supporting evidence; where none exists, mark the control "no evidence found" rather than inferring compliance.
3. Score each control's maturity on a consistent scale (e.g. 0 None / 1 Initial / 2 Defined / 3 Managed / 4 Optimized) and classify the gap as Met / Partial / Gap. Cite the evidence (or its absence) behind every score.
4. Build a remediation roadmap: group gaps by severity and effort, sequence them, and name an owner placeholder per item. Report the scored assessment, an overall maturity summary, the assumptions made on scope/version, and hand off to the control owner / GRC lead for validation and prioritization sign-off.

# Notes

The output is wrong if a control is scored "Met" without cited evidence, if framework version/scope is guessed silently, or if maturity scores use an inconsistent scale across controls. Internal knowledge can be stale — mark evidence that is unverified or older than the audit period. This is a readiness draft and recommendation only: it does not constitute an audit opinion, certification, or attestation, and accepting/closing a gap is a human GRC decision. Do not use to assert "we are compliant" externally.
