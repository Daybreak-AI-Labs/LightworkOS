---
name: regulatory-exam-prep
triggers:
  - prepare for a regulatory exam
  - respond to an examiner request list
  - build our exam prep package
tools_needed:
  - knowledge_search
---
# What this skill does

Prepares an organization for a regulatory examination: maps each examiner request-list item to responsive evidence, drafts control/process narratives, and assembles an exam-prep package. Produces a request-to-evidence matrix plus supporting narratives that an exam team and legal can review before submission.

# Steps

1. Establish scope from the request: which regulator, exam type, in-scope period, and the examiner request list (the formal items/PRT). Use `knowledge_search` to retrieve the request list, applicable rules/guidance, and the org's policies, controls, and prior exam findings — cite each source; if a request list item is ambiguous, flag it for clarification rather than assuming intent.
2. Build the request-mapping matrix: one row per request item, mapped to specific responsive artifacts (policies, reports, evidence) located via search, with owner, location/link, and status. Mark items with no located evidence as a GAP — never present an unverified or missing artifact as available.
3. Draft control/process narratives for each themed area: what the control is, how it operates, the governing requirement (cited), and how the attached evidence demonstrates it. Note where evidence is partial or where a prior finding remains open, with its remediation status.
4. Assemble the exam-prep package: matrix, narratives, evidence index, and a gap/risk list of unmappable requests and weak areas. Report it with assumptions and gaps stated; route to compliance and legal for review — do not submit to the examiner. Final responses and submission are human decisions.

# Notes

Output is wrong if an artifact is mapped to a request without confirming it exists and is responsive, if a narrative cites a requirement that was not verified, or if a gap is silently omitted. Anything you could not locate must read as a gap, not a pass. This skill drafts the package and recommends; what is produced to an examiner, how questions are answered, and any privilege call are irreversible and reserved for compliance/legal. Not for general policy authoring or for live remediation of findings — those are separate workflows.
