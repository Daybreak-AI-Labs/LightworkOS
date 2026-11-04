---
name: crisis-management-playbook
triggers:
  - prepare a crisis management playbook
  - we need an incident command structure
  - draft our crisis comms plan
tools_needed:
  - knowledge_search
---
# What this skill does

Prepares a crisis-management playbook for an organization: defined roles and an incident-command structure, internal/external communications protocols and templates, and severity-tiered decision gates. Produces a draft playbook that tells responders who does what, who they tell, and what decisions require which authority during a crisis.

# Steps

1. Establish scope from the request: which crisis types (operational outage, data breach, safety, legal/regulatory, reputational) and which org/jurisdictions. Use `knowledge_search` to pull existing crisis/IR policy, org chart, on-call rosters, regulatory notification obligations, and prior incident reviews — cite each; mark missing roles or obligations as gaps, do not invent contacts.
2. Define the incident-command structure: Incident Commander, comms lead, legal/compliance, ops, and scribe, with primary and backup named owners and activation thresholds per severity tier. Where a role has no named owner in the source data, leave it as TO ASSIGN rather than guessing.
3. Build communications protocols: internal escalation chain, holding statements and stakeholder templates (staff, customers, regulators, press), approval path per message, and statutory notification timelines with their cited source. Flag any regulatory clock as unverified if you could not confirm the obligation.
4. Define decision gates per severity: declare/stand-down criteria, who authorizes public statements, regulator notification, and recovery actions. Report the playbook draft with assumptions, unassigned roles, and unconfirmed obligations listed; route to crisis-response leadership for sign-off — it is a draft until exercised and approved.

# Notes

Output is wrong if it names responders not confirmed in the source roster, asserts notification deadlines without citing the governing requirement, or omits a crisis type in scope. Legal and regulatory notification timing must be cited or marked unverified — never fabricated. This skill drafts and recommends; declaring a crisis, sending external statements, and notifying regulators are irreversible actions reserved for the authorized humans named in the gates. Not for the underlying technical recovery (use the disaster-recovery plan) or process-level impact analysis (use the business-continuity plan).
