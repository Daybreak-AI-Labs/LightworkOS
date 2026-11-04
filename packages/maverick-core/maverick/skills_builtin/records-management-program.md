---
name: records-management-program
triggers:
  - records management program
  - information governance file plan
  - build a retention schedule
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a records & information governance (RIM) program for a defined scope (an organization, function, or system) and produces a draft deliverable: a file plan (record-series taxonomy), a retention schedule mapped to legal/regulatory citations, and disposition rules including legal-hold handling. Output is a program design for the records owner and legal/compliance to ratify, not an authorization to destroy records.

# Steps

1. Define scope and inventory inputs from the requester: the units/systems/record types in scope, the regulatory and contractual environment, and current storage locations and formats. Inventory the record series actually present — base series on real holdings, not a generic template; mark series you inferred for confirmation.
2. Use `knowledge_search` to find the governing retention authorities for each series (statutory/regulatory minimums, tax, employment, sector rules, contractual obligations, applicable standards like ISO 15489). Cite the specific citation and minimum period per series; where authorities conflict or overlap, default to the longest required period and flag it.
3. Build the file plan and retention schedule: organize record series into a taxonomy (function -> series), assign each series a trigger event (creation/event/superseded), retention period with citation, and a disposition action (destroy / transfer to archive / review). Define legal-hold override rules that suspend disposition and the metadata needed to enforce them.
4. Specify the disposition workflow and program controls: who approves destruction, the certificate-of-destruction requirement, hold-clearance check before any purge, and an audit trail. Report the draft RIM program (file plan + schedule + disposition rules) with citations and assumptions, and hand off to the records owner and legal for ratification before any retention rule goes live.

# Notes

The destructive end of the lifecycle is where harm happens: a retention period set below a legal minimum, or disposition that runs while a legal hold is active, can constitute spoliation — so every period must carry a citation and legal hold must override all disposition. Longest-applicable-period is the safe default when authorities overlap; never schedule below a cited minimum. Schedules go stale as laws change; mark the schedule with the date/version of authorities searched and recommend periodic review. This skill drafts and recommends the program; approving the schedule, applying holds, and authorizing any actual destruction are human decisions requiring records-owner and legal sign-off. Do not use to execute deletions, to make per-document privilege calls, or to design e-discovery collection (related but distinct).
