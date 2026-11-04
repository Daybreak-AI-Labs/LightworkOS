---
name: audit-finding-remediation
triggers:
  - plan audit finding remediation
  - corrective action plan for findings
  - close out audit findings
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

Turns a set of audit findings into an actionable remediation plan. Produces a tracked plan where each finding has a corrective action, an accountable owner, the evidence required to prove closure, and a target/committed completion date.

# Steps

1. Pull the audit findings from knowledge_search (finding ID, description, severity, control/requirement reference, source report). If findings lack severity or a control reference, flag them — don't assign dates without it.
2. For each finding, retrieve the related control and any prior remediation history via knowledge_search to avoid duplicating or re-opening closed items. Cite the source finding for each row.
3. Draft a corrective action per finding and propose an owner (by role from the control ownership records, not a guessed name — mark unverified owners). Define the closure evidence required and a target date scaled to severity.
4. Build the plan in spreadsheet (finding, action, owner, evidence, target date, status) and hand it off marked DRAFT FOR OWNER CONFIRMATION, stating which owners and dates are proposed vs. confirmed.

# Notes

A plan is wrong if owners are assigned without their confirmation, if closure "evidence" is vague (so a finding can be marked closed without proof), or if target dates ignore severity. This skill drafts and recommends; it does not close findings — sign-off, evidence acceptance, and closure are human decisions by the control owner and audit. Do not use it to mark findings closed, and do not use it when findings lack a traceable control/requirement reference.
