---
name: rpa-pdd-author
triggers:
  - write a pdd
  - rpa design document
  - bot specification
tools_needed:
  - knowledge_search
---
# What this skill does

Authors a Process Definition Document (PDD) for an RPA bot: the as-is procedure captured step by step with inputs, outputs, business rules, exceptions, and control points, at enough fidelity that a developer can build and an auditor can review. Produces a structured PDD draft ready for SME sign-off.

# Steps

1. Gather the source procedure from real inputs — SOPs, recorded walkthroughs, process-mining variants, or SME notes via knowledge_search. Identify the trigger, the systems/applications touched, credentials/roles required, and the in-scope happy path. Mark any step you could not confirm as UNVERIFIED.
2. Document the keystroke-level steps in order: for each, the action, the input fields and their source, the expected output, and the business rule applied. Capture screen/system names exactly as the SME states them; do not guess UI labels.
3. Enumerate exceptions and their handling: business exceptions (e.g. missing data, validation failure) vs system/application exceptions (timeout, app down), and for each the route — retry, queue for human, or abort. Define control points: validation checks, reconciliation totals, and audit-log entries the bot must write.
4. Assemble the PDD draft — purpose, scope, trigger, prerequisites, step table, exception table, control points, volumes/SLA, and a sign-off block. Hand off to the named SME for verification, listing every UNVERIFIED step and open question.

# Notes

A PDD is wrong when it documents the should-be instead of the observed as-is, or invents UI labels and field names the developer then can't find — keep it grounded in the recorded process. Underspecified exception handling is the top cause of bot breakage in production; do not leave an exception with no defined route. Skip this skill for judgment-heavy or constantly-changing processes that are poor RPA fits — flag those back rather than documenting them. The PDD is a draft until SME sign-off; do not treat it as build-approved.
