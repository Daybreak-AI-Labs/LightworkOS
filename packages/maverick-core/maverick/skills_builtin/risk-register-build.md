---
name: risk-register-build
triggers:
  - build a risk register
  - create a risk log
  - rate the project risks
tools_needed:
  - spreadsheet
  - knowledge_search
---
# What this skill does

Catalogs and rates project or operational risks into a structured register: each risk scored on likelihood and impact, assigned an owner, and paired with a mitigation and contingency. Produces a sortable spreadsheet that drives prioritization and review, not a freeform list of worries.

# Steps

1. Collect candidate risks from the real context — project plan, incident history, dependencies, assumptions. Use `knowledge_search` for prior registers, postmortems, and known organizational risks. Capture each risk as a single clear cause-and-effect statement; do not pad the list with generic boilerplate.
2. For each risk, record category, description, likelihood (e.g. 1-5), impact (1-5), and computed severity (likelihood x impact). State the basis for each score; mark a score as ESTIMATED when it rests on judgment rather than data.
3. Assign an accountable owner and a mitigation (reduce probability/impact) plus a contingency (if it occurs). Write these into the `spreadsheet` with columns: id, category, risk, likelihood, impact, severity, owner, mitigation, contingency, status.
4. Sort by severity, flag the top risks for escalation, and report the register. State assumptions and note which owners are proposed vs confirmed — owner assignment is a recommendation for a human to ratify.

# Notes

The register is wrong if scores are unjustified, if risks are vague ("things may go wrong"), or if one row bundles several distinct risks. Owners and mitigations are drafts; accepting, transferring, or closing a risk is a human decision. Do not fabricate likelihoods to fill cells — mark gaps. Not for incident response in progress (use an incident runbook) or for a single one-off risk that needs no tracking.
