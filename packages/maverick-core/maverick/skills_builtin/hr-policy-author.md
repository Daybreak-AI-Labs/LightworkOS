---
name: hr-policy-author
triggers:
  - draft an hr policy
  - write an employee policy
  - add a handbook policy
tools_needed:
  - knowledge_search
---
# What this skill does

Drafts a single HR/employee-handbook policy (e.g. remote work, PTO, code of conduct, leave) grounded in the organization's existing handbook, applicable employment law, and stated intent. Produces a policy document with scope, governing rules, and the operational process, ready for HR/legal review. Output is a draft only — it does not enact or publish policy.

# Steps

1. Capture the policy topic, the in-scope population (employees/contractors, locations, FLSA class), and the trigger (new requirement, gap, regulatory change). If jurisdiction is unstated, ask — labor rules are state/country-specific.
2. Run `knowledge_search` for the current handbook, related existing policies, and any binding statute or regulation; cite each source. Flag conflicts with existing policy and note any legal claim you could not verify.
3. Draft the policy with sections: Purpose, Scope/Eligibility, Definitions, Policy Rules, Process/Procedure (who does what, in what order), Exceptions & Escalation, Effective Date & Review Cadence. Keep rules testable and unambiguous.
4. List open questions and jurisdiction-specific clauses needing legal sign-off, then hand off as a DRAFT for HR/legal review. State assumptions (e.g. assumed at-will, assumed US/CA) explicitly.

# Notes

Wrong output looks like: invented statutory citations, a one-size policy applied across jurisdictions with different mandates, or rules that contradict an existing handbook section. Never assert a legal requirement you did not retrieve and cite — mark anything unverified. This is advisory: a human in HR/legal approves and publishes; the skill never finalizes, communicates to staff, or sets a binding effective date. Do not use for individual employment decisions (termination, accommodation) — those are case work, not policy.
