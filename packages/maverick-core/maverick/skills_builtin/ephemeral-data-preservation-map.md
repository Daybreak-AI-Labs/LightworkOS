---
name: ephemeral-data-preservation-map
triggers:
  - preserve chat data
  - slack teams legal hold
  - ephemeral message custodian map
  - modern data preservation matrix
tools_needed:
  - knowledge_search
---
# What this skill does

This skill builds the custodian-by-data-source preservation matrix needed when a litigation hold reaches "modern" and ephemeral data — Slack/Teams messages, SMS/iMessage, collaboration tools, and disappearing-message apps — where default retention settings can silently destroy discoverable evidence. It maps each custodian against each data source, records the source's current retention/auto-delete setting, and flags spoliation risk where ephemerality or auto-deletion could defeat the duty to preserve. The output is a preservation matrix and a prioritized list of retention settings that must be suspended; it stages recommendations for legal/IT to execute — it does not itself change any retention setting or issue a hold.

# Steps

1. Use knowledge_search to pull the litigation-hold scope (matter, trigger date, relevant time period, issues) and the org's data-source inventory and retention schedule, and to enumerate the candidate modern/ephemeral sources in use (Slack, Teams, Google Chat, SMS/iMessage on managed devices, Zoom chat, ticketing, and any disappearing-message tools).
2. Build the matrix: rows = custodians in scope, columns = data sources. For each cell, mark whether the custodian uses that source and capture the source's current retention behavior (indefinite, N-day auto-delete, user-controlled disappearing messages, off by default).
3. Flag spoliation risk per cell: any source with auto-deletion, user-controlled ephemerality, or short retention that overlaps the relevant period is a HIGH-risk cell where the auto-delete/retention setting must be suspended to meet the preservation duty. Note sources where preservation requires an admin/in-place hold versus an export.
4. Assemble the preservation matrix plus a prioritized action list (which retention settings/auto-delete rules to suspend, per source, and which custodians to notify) and stage it for legal and IT. Mark that issuing the hold and changing retention settings are human/admin actions — this skill maps and recommends, it does not execute.

# Notes

Ephemeral and auto-delete settings are the spoliation trap: a Slack workspace or disappearing-message app that keeps deleting during the relevant period defeats the preservation duty even if no one intends it — that is exactly what this matrix exists to surface, so flag every auto-deleting source loudly. Preservation method varies by source: some need an in-place/legal hold toggled by an admin, others a forensic export — note which, since "we told them to keep it" is not preservation for a user-controlled disappearing app. Personal devices and BYOD raise privacy/scope limits; flag them rather than assuming access. This skill produces a matrix and a recommended action list — it does not toggle retention, issue the hold, or collect data; those are human/admin steps. Capture the trigger date precisely, since the duty to preserve runs from it.
