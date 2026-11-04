---
name: privacy-dpia
triggers:
  - dpia
  - data protection impact assessment
  - privacy impact assessment
tools_needed:
  - knowledge_search
---
# What this skill does

Assesses a high-risk personal-data processing activity and produces a Data Protection Impact Assessment: the processing description, necessity and proportionality analysis, risks to data subjects, and mitigations with residual-risk ratings. Gives a DPO or privacy lead a structured, source-cited record to review and sign before processing begins.

# Steps

1. Describe the processing: purpose, data categories (flagging special-category/sensitive data), data subjects, volume, retention, recipients and cross-border transfers, and the lawful basis. Pull these from the system's data-flow / RoPA record via knowledge_search; cite each source and mark any field you could not verify as a gap to confirm, never fabricate.
2. Test whether a DPIA is required and whether the processing is necessary and proportionate: can the purpose be met with less data, shorter retention, or stronger pseudonymization? Document the necessity rationale and any less-intrusive alternative considered and rejected, with reasons.
3. Identify risks to data subjects (unauthorized access, re-identification, discrimination, function creep, loss of control, automated decisions) and rate each by likelihood × severity. For each, specify mitigations (minimization, encryption, access controls, DPA terms, opt-outs) and the residual risk after mitigation.
4. Compile the DPIA with a clear recommendation (proceed / proceed-with-conditions / consult regulator) and list open gaps from step 1. State that ratings reflect current controls and hand off to the DPO; do not authorize processing or sign off — the assessment is a draft for the accountable owner's decision.

# Notes

The DPIA is wrong if it asserts a lawful basis or control that isn't actually in place — every claim must trace to a source or be marked unverified; invented controls create false assurance and legal exposure. High residual risk after mitigation may legally require prior regulator consultation — flag it, don't bury it. This is advisory: it recommends, it does not approve processing or replace legal counsel; the accountable owner (DPO/controller) signs the irreversible go-decision. Not a substitute for a vendor security review or a full RoPA. Cite the applicable regime (GDPR Art. 35, UK GDPR, state law) rather than assuming one.
