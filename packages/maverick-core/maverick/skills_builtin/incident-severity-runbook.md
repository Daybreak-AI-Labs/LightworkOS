---
name: incident-severity-runbook
triggers:
  - incident severity
  - incident triage
  - sev levels
---
# What this skill does

Produces a severity-classification runbook for security incidents: a small ladder of severity levels (e.g. Sev1-Sev4) with objective entry criteria, the routing and escalation path per level, response-time targets, and notification obligations. Produces a draft runbook responders can apply consistently under pressure.

# Steps

1. Pull the org's existing IR policy, on-call structure, and any regulatory breach-notification duties via knowledge_search; cite them. Capture the dimensions that should drive severity: data sensitivity affected, scope/blast radius, system criticality, and active-attacker indicators.
2. Define 3-4 severity levels with mutually exclusive, observable entry criteria stated as thresholds (e.g. "confidential data confirmed exfiltrated", "production customer-facing service down") — not adjectives. The criteria must let two responders independently land on the same level.
3. For each level specify the routing: who is paged, the response-time / acknowledgment target, who declares the incident, and the escalation trigger that bumps it up a level. Tie notification obligations (regulator, customer, exec, legal) to the levels where a cited rule requires them.
4. Add a triage decision flow and 2-3 worked example incidents mapped to levels, including one that escalates mid-incident, drawn from real past incidents if retrievable (knowledge_search) rather than invented.
5. Report the runbook as a draft, state assumptions and any escalation path left undefined by missing org inputs, and route to the IR lead / SOC owner for adoption — flag that severity declaration during a live incident remains a human call.

# Notes

The runbook is wrong if two levels share overlapping criteria, if a level has no defined owner/escalation, or if a stated notification deadline misstates the actual regulatory clock — verify deadlines against a retrieved source, never from memory. Do not fabricate notification timelines or example incidents. This drafts and recommends; declaring severity and triggering external notifications on a live incident are human decisions staged for approval. Do not use it to triage one specific in-flight incident (that's applying an existing runbook) or to replace legal's breach-notification determination.
