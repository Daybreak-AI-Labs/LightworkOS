---
name: regulatory-change-impact
triggers:
  - assess the impact of a new regulation
  - regulatory change impact
  - new rule just came out, what do we need to do
  - reg change assessment
tools_needed:
  - knowledge_search
  - web_search
---
# What this skill does

Assesses how a new or amended regulation affects the organization's operations, policies, and controls. Produces a reg-change impact assessment: the concrete obligations the rule imposes, the affected processes/systems/policies, a gap analysis against current state, and prioritized remediation actions with the effective/compliance deadline. Output is a draft assessment for compliance and legal review.

# Steps

1. Pin the exact instrument from the input: regulator, rule citation, version/amendment, publication and effective dates. Use `web_search` to retrieve the authoritative text (regulator or official gazette source) — cite it; if you can only find secondary commentary, mark obligations "derived from secondary source — confirm against primary text."
2. Extract the discrete obligations (what must be done, by whom, by when, with what evidence). List each as a testable requirement, not a paraphrase of the preamble.
3. Map obligations to the current state: `knowledge_search` existing policies, controls, and process owners to find what already satisfies each obligation and where gaps exist. Tag each obligation: covered / partial / gap / unknown-owner.
4. Build the deliverable: obligation register, gap analysis, prioritized remediation actions (owner, effort, deadline driven by the compliance date), and residual risk. Report with assumptions stated; remediation actions are RECOMMENDATIONS — a compliance owner decides what to commit.

# Notes

Wrong if: obligations are read from secondary commentary instead of the primary instrument, the effective/compliance date is missed (it drives every deadline), or applicability isn't checked (the rule may not cover your entity size, sector, or jurisdiction — confirm scope before assessing). Distinguish "in force" from "proposed/consultation" — never assess a draft rule as binding. Do not use for routine policy refreshes with no external trigger. This produces an assessment, not legal advice; counsel signs off on interpretation.
