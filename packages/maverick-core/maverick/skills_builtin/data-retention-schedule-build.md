---
name: data-retention-schedule-build
triggers:
  - retention schedule
  - data retention
  - how long to keep
tools_needed:
  - knowledge_search
---
# What this skill does

Builds a records-retention schedule for a set of record classes: for each class, the retention trigger (the event that starts the clock), the retention period, the legal/business basis, and the disposition action at end of life. Produces a defensible draft schedule a records owner or counsel can approve.

# Steps

1. Enumerate the record classes in scope from the request or the org's data inventory (knowledge_search) — group by record type and function, not by storage system. Do not invent classes; if the inventory is partial, list only what is grounded and flag the gap.
2. For each class, identify the retention trigger precisely: creation, last-activity, contract-end, employee-termination, or fiscal-year-close. An ambiguous trigger makes the period unenforceable, so name the exact event.
3. Set the retention period and cite its basis: statutory/regulatory minimum (knowledge_search the specific rule), contractual obligation, or business need. Where multiple bases apply, the longest controlling requirement wins — record which one governs. Mark business-need-only periods as discretionary.
4. Specify disposition at end of period (secure destroy, anonymize, archive, transfer-to-archive-of-record) and any legal-hold override that suspends the clock. Note conflicts where a deletion mandate (e.g. GDPR erasure) collides with a retention minimum.
5. Report the schedule as a draft table (class, trigger, period, basis, disposition), state assumptions and unresolved legal conflicts, and route to records management / legal for sign-off — do not authorize any actual deletion.

# Notes

The schedule is wrong if a period lacks a cited basis, a trigger is vague, or a regulatory minimum is understated — verify each period against a retrieved source, never from memory. Do not fabricate statutory periods; if you cannot confirm one, mark it unverified and flag for counsel. Disposition is irreversible: this skill only drafts and recommends — a human owner approves before anything is destroyed, and legal holds always override. Do not use it to actually execute deletions or to override an active hold.
