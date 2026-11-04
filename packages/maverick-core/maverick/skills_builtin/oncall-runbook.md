---
name: oncall-runbook
triggers:
  - write an oncall runbook
  - service runbook for the pager
  - pager runbook
tools_needed:
  - knowledge_search
---
# What this skill does

Writes an on-call runbook for a single service so a paged responder can triage and recover without tribal knowledge. Produces a structured document: each alert's meaning, a triage decision tree, recovery procedures with explicit commands, and escalation paths — grounded in the service's real alerts and dependencies.

# Steps

1. Enumerate the service's active alerts, dependencies, and known failure modes via `knowledge_search` (existing alert definitions, past incidents, dashboards). Do not invent alerts that aren't configured.
2. For each alert write: what it means, likely causes, first dashboards/queries to check, and a triage branch (is it this service, a dependency, or upstream?). Link to the relevant SLI/dashboard.
3. Document recovery procedures step by step with the exact commands or console actions, and clearly mark every destructive or irreversible step (restart, failover, scale-down, data deletion) as requiring confirmation — stage it, do not auto-run.
4. Hand off the runbook with escalation contacts/rotations, rollback steps, and a "if all else fails" path. State assumptions (access prerequisites, tooling) and mark any procedure not validated against a real incident as unverified.

# Notes

A runbook is dangerous when wrong: a confidently-worded but untested recovery step can deepen an outage. Mark unverified steps, cite the incident or doc each procedure came from, and never present a destructive command as safe to run blind — the responder (a human) decides and executes irreversible actions. Keep it skimmable: a responder reads this at 3am under pressure. Not for designing the alerts/SLOs themselves (use observability-design / slo-error-budget-policy) or for post-incident review writeups.
