---
name: incident-severity-classification
triggers:
  - what severity is this incident
  - sev classification for this outage
  - how bad is it, who do we page
tools_needed:
  - knowledge_search
---
# What this skill does

Triages an active or reported incident to a severity level (e.g. SEV1-SEV4) using the organization's own severity rubric, and produces the escalation path that level demands. Handles the goal class "an incident is happening — how bad is it, and who must be notified." Produces a classification with the impact evidence behind it and the on-call/escalation chain to engage.

# Steps

1. Gather the incident facts from the report: what is broken, blast radius (users/tenants/regions affected), whether it is customer-facing, data loss or security exposure, and whether a workaround exists. Distinguish observed facts from assumptions; note unknowns explicitly — do not invent impact numbers.
2. Retrieve the authoritative severity rubric and escalation policy via `knowledge_search` (runbook, incident-management policy). Use the org's defined thresholds, not generic ones — if no rubric is found, say so and fall back to a clearly-labeled generic SEV scale.
3. Map the facts to the highest severity whose criteria are met (severity is the worst matching tier, not the average). Record which specific criterion triggered the level (e.g. "data-loss risk -> SEV1") so the call is auditable.
4. Report: assigned severity, the matched criteria and supporting evidence, the required escalation path (who to page, comms cadence, IC needed), and the unknowns that could raise or lower it. State assumptions and recommend re-triage if blast radius changes.

# Notes

The classification is wrong if it under-rates by averaging criteria, relies on a generic scale when an org rubric exists, or treats assumed impact as confirmed. Severity drives paging and customer comms, so err toward the higher tier when evidence is ambiguous and say why. This recommends a severity and escalation path; actually paging people, declaring a public SEV1, or sending customer notifications is a human decision — stage it, don't execute. Do not use for post-incident review or root-cause analysis (that is retrospective, not triage), or for non-incident bug prioritization.
