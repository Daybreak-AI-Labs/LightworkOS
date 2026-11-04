---
name: gdpr-lawful-basis-assessment
triggers:
  - lawful basis
  - gdpr basis
  - legitimate interest
tools_needed:
  - knowledge_search
---
# What this skill does

Determines and documents the GDPR Article 6 lawful basis for a specific processing activity (and Article 9 condition where special-category data is involved). Produces a per-purpose lawful-basis assessment, including a Legitimate Interests Assessment (LIA) when legitimate interest is relied upon. Output is a defensible record an organization can place in its Article 30 documentation.

# Steps

1. Pull the concrete processing facts from the request: the purpose, data categories, data subjects, retention, and whether special-category (Art. 9) or criminal-offence (Art. 10) data is in scope. Do not infer facts not given; mark gaps as "to confirm."
2. Use knowledge_search to retrieve the relevant GDPR articles and the controller's existing records (privacy notice, ROPA entry, prior DPIAs) for this purpose. Map each distinct purpose to one of the six Art. 6 bases — never default to "consent" or "legitimate interest" without testing fit.
3. Where legitimate interest is the candidate basis, run the three-part LIA: (a) identify the interest and confirm it is legitimate, (b) necessity — is processing required and proportionate, (c) balancing — weigh against the data subject's rights, reasonable expectations, and any safeguards. Record the outcome and any opt-out. For Art. 9 data, additionally select an Art. 9(2) condition.
4. Report a table of purpose -> basis -> Art. 9 condition (if any) -> supporting rationale, flagging any purpose where no basis cleanly applies, and hand off the draft for DPO/legal sign-off. State all "to confirm" assumptions explicitly.

# Notes

Wrong if a single basis is stretched across multiple purposes, if consent is asserted without a withdrawal mechanism, or if special-category data is processed on an Art. 6 basis alone (it needs an Art. 9 condition too). Citations to articles must be exact; mark anything unverified. This is a drafting and recommendation step — the DPO or legal counsel makes the final determination, and basis cannot be silently switched later. Do not use for jurisdictions outside GDPR/UK GDPR scope (use the CCPA/CPRA skill for California).
