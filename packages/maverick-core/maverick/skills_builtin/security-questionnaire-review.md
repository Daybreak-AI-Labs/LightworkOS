---
name: security-questionnaire-review
triggers:
  - review this security questionnaire
  - vendor questionnaire came back
  - due diligence on a vendor's responses
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Reviews an inbound security questionnaire response from a vendor (CAIQ, SIG, or a custom set) and turns it into an analyst verdict: which answers are adequate, which are red flags, which contradict each other or the supplied evidence, and what to ask next. Produces a structured review with per-question findings, a red-flag list, and a follow-up request list. Use it to triage a returned questionnaire before a TPRM analyst signs off.

# Steps

1. Read the questionnaire response and any attached evidence (SOC 2 report, pen-test summary, policies) via read_file. Identify the framework and the control areas covered (access control, encryption, incident response, BC/DR, subprocessors, data residency). Note any questions left blank or answered "N/A" — track them; do not treat blanks as passes.
2. For each control area, compare the vendor's answer against the organization's minimum security requirements (pull them via knowledge_search). Flag answers that fall below the bar, are vague/non-committal ("we follow industry best practice" with no specifics), or claim a control the attached evidence does not corroborate.
3. Cross-check answers for internal contradictions (e.g. "data encrypted at rest" but a later answer says a legacy store is plaintext) and against the SOC 2 scope/exceptions. Cite the question number and the conflicting source for every red flag so the finding is traceable; mark any claim with no supporting evidence as "asserted — unverified".
4. Write the review: per-area verdict (adequate / gap / red flag), a consolidated red-flag list ranked by severity, and a precise follow-up question list the analyst can send back. State that this is an advisory review — the accept/reject and risk-acceptance decision belongs to the TPRM owner.

# Notes

The output is wrong if a vague or evasive answer is scored as adequate, if a claimed control is accepted without checking the attached evidence, or if a red flag is raised without citing the question and the contradicting source. SOC 2 exceptions and a report's scope/date are the usual place a "compliant" vendor falls down — always read them, not just the cover. Never fabricate a control requirement; if the org's minimum bar is unknown, say so. This produces a recommendation only; do not approve, reject, or issue a risk acceptance. Do not use to assess inherent risk or to set a vendor's tier — that is upstream.
