---
name: business-continuity-plan
triggers:
  - build a business continuity plan
  - we need a BCP
  - run a business impact analysis
tools_needed:
  - knowledge_search
---
# What this skill does

Builds a business-continuity plan (BCP) for a named organization or business unit: a documented Business Impact Analysis (BIA), per-process RTO/RPO targets, and step-by-step recovery procedures. Produces a structured BCP draft that ties critical processes to their dependencies, impact tolerances, and the actions to restore them after a disruption.

# Steps

1. Establish scope from the request: which entity, business units, and disruption classes (outage, site loss, supplier failure, cyber, pandemic). Use `knowledge_search` to pull the org's process inventory, existing continuity policy, and any prior BIA — cite each source; mark anything absent as a gap, do not invent processes.
2. Run the BIA: for each critical process, search for and record its dependencies (people, systems, suppliers, data, facilities), the impact of downtime over time (financial, regulatory, reputational), and the Maximum Tolerable Period of Disruption. Where impact data is missing, flag as unverified and request owner input rather than estimating.
3. Derive RTO and RPO per process from the MTPD and data-loss tolerance; rank processes into recovery tiers. Note any process whose current capability cannot meet its RTO/RPO as a residual risk.
4. Draft recovery procedures per tier (workarounds, failover, manual mode, relocation), assign process and recovery owners, and define activation/escalation triggers. Report the BCP draft with an explicit list of assumptions, gaps, and unmet RTO/RPO targets; route to the continuity owner for validation — do not mark it approved.

# Notes

Output is wrong if RTO/RPO are asserted without a BIA basis, if dependencies are guessed rather than sourced, or if processes are omitted because they weren't in the searched corpus — completeness depends on the inventory you can actually find, so state coverage. This skill drafts and recommends; activating a plan, committing recovery budget, or declaring a process out of scope is an irreversible governance decision a human owner must make. Do not use it for live incident response (use the crisis-management playbook) or for IT-system recovery detail (use the disaster-recovery plan).
