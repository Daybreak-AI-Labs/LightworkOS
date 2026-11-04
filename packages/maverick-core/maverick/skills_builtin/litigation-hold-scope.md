---
name: litigation-hold-scope
triggers:
  - legal hold
  - litigation hold
  - preserve evidence
tools_needed:
  - knowledge_search
---
# What this skill does

Scopes a legal hold for anticipated or filed litigation: identifies the matter's likely evidence, the people who control it (custodians), and where it lives (systems and repositories), then drafts a preservation notice. Produces a defensible hold scope a human attorney reviews and issues. Handles the recurring task of converting a triggering event into a concrete, auditable preservation plan.

# Steps

1. Pull the matter facts from the triggering input: claims/parties, relevant date range, subject matter, and the reasonable-anticipation date. Do not invent a date — if the trigger event is unstated, flag it as a required input.
2. Use `knowledge_search` against case files, org charts, and prior holds to enumerate custodians (decision-makers, named individuals, their managers/assistants) and data sources (email, chat, file shares, ticketing, ERP/CRM, devices, backups, third-party SaaS). Cite the source for each custodian; mark any inferred custodian as unverified.
3. Map each custodian to their sources and to retention/auto-deletion settings that must be suspended (mailbox retention, chat TTL, backup rotation). Note ESI formats and any data outside the org's control (personal devices, vendors) requiring a separate request.
4. Draft the preservation notice (scope, date range, acknowledgment requirement, suspension-of-deletion language) and a custodian/source matrix. Report the scope, list explicit assumptions (date range, completeness of custodian list), and hand off to counsel for issuance.

# Notes

Output is wrong if it omits a custodian, misses an auto-deletion source, or sets too narrow a date range — under-preservation risks spoliation sanctions. The skill drafts and recommends only; issuing the hold, suspending retention, and any deletion suspension are legal decisions a human attorney authorizes. Never represent the scope as complete without source citations. Do not use for active discovery production, collection, or review — this stops at preservation scope.
