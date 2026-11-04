---
name: incident-response-playbook
triggers:
  - incident playbook
  - ir playbook
  - response runbook for this incident type
tools_needed:
  - knowledge_search
---
# What this skill does

Prepares an incident-response playbook for a specific incident type (e.g., ransomware, credential compromise, data exfiltration, service outage). Produces a structured runbook covering detection, containment, eradication, recovery, plus roles, escalation, and communication steps — aligned to the org's existing IR policy and the standard NIST-style lifecycle.

# Steps

1. Confirm the incident type and scope, then pull the org's existing IR policy, on-call/escalation roster, asset inventory, and any prior post-mortems with `knowledge_search`. Build on what exists — do not invent contacts, system names, or tooling the org doesn't have.
2. Draft the lifecycle phases for this incident type: Detection (signals, alert sources, triage criteria), Containment (short-term isolate vs. long-term), Eradication (root-cause removal), and Recovery (restore, validate, monitor). Ground each step in real systems named in the inventory; mark any referenced tool you couldn't confirm as [UNVERIFIED].
3. Add the operational wrap: roles (incident commander, comms lead, scribe), escalation thresholds and who to page, evidence-preservation/forensics notes, and internal/external/regulatory communication steps with timing. Flag any legal or breach-notification step as requiring counsel sign-off.
4. Hand off the playbook stating which steps are policy-backed vs. drafted from best practice, and list the destructive actions (isolating hosts, wiping/reimaging, revoking access, restoring from backup) that must be staged for an on-call human and not auto-executed.

# Notes

A playbook is dangerous when it hard-codes containment actions as automatic — isolation, key rotation, reimaging, and backup restores are irreversible or service-affecting and must be human-approved at execution time. It's wrong when it references tools, runbooks, or contacts the org doesn't actually have; verify against the inventory or mark unverified. Breach-notification timing and forensic-evidence handling carry legal weight — defer to counsel, don't assert deadlines. This produces a prepared template to rehearse and approve; it is not live incident command and does not replace the on-call IC during an active incident.
