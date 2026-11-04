---
name: sop-author
triggers:
  - write an SOP for this process
  - document the process as a standard operating procedure
  - we need a repeatable runbook for this task
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Turns a fuzzy, tribal-knowledge business process into a standardized SOP that any qualified person can execute the same way every time. Produces a structured document with scope, roles/RACI, numbered procedure steps, and the controls (checks, approvals, evidence) that keep the process compliant and auditable.

# Steps

1. Capture the real process: pull existing runbooks, tickets, or prior SOPs via `knowledge_search` and `read_file`; if a step has no source, mark it "[unverified — confirm with process owner]" rather than guessing.
2. Define scope and boundaries — what this SOP covers, what it explicitly does not, trigger/entry condition, and the completion/exit criterion.
3. Assign roles: list every actor and map each step to one accountable owner (RACI). Flag any step where the owner is ambiguous.
4. Write the procedure as numbered, imperative steps with decision branches and exception handling; embed controls inline (approval gates, validations, required evidence/records, segregation of duties).
5. Report the SOP with a revision/owner/effective-date header and a list of open questions; state that step ownership and control thresholds are assumptions until the process owner signs off.

# Notes

Output is wrong if steps describe the aspirational process instead of what people actually do — always ground in captured sources and label inferred steps. Do not invent control thresholds, regulatory references, or approval chains; cite the source or mark unverified. The SOP is a draft for the process owner to ratify — do not present it as the official controlled document, and do not use this skill for one-off tasks that won't recur (no SOP needed) or for safety/regulatory procedures requiring formal qualified sign-off, which a human must own.
