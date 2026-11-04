---
name: records-retention-schedule
triggers:
  - build a records retention schedule
  - how long do we keep these records
  - define retention periods
  - records retention policy
tools_needed:
  - knowledge_search
---
# What this skill does

Defines how long each class of records must be retained, the trigger that starts the clock, and what happens at end of life. Produces a retention schedule: record classes mapped to retention periods with cited legal/regulatory basis, legal-hold overrides, and a disposition action (destroy, archive, transfer) per class. Output is a draft schedule for records-management review.

# Steps

1. Inventory the real record classes in scope from the source provided (file plan, system inventory, or business unit list). Group into classes — do not invent classes that aren't represented in the inputs.
2. For each class, `knowledge_search` the applicable retention authority (statute, regulator rule, tax/SOX/HR/contract requirement) and capture the required period AND its retention trigger (creation date, contract termination, last activity, fiscal year close). Cite each source; mark any class with no found authority as "no statutory basis found — set by business policy, needs owner sign-off."
3. Resolve conflicts by the longest-applicable rule, and flag classes subject to legal hold as indefinite/suspended-disposition until the hold lifts.
4. Assemble the schedule table (class, basis + citation, period, trigger, disposition action, hold flag) and report. State assumptions; disposition/destruction is STAGED — a records manager approves before anything is destroyed.

# Notes

Wrong if: a period is stated without a cited authority, the retention trigger is omitted (a period with no start date is unusable), or a legal hold is overridden by a disposition. Destruction is irreversible — never auto-dispose; produce the schedule and let a human authorize each destruction run, and confirm no active hold or pending litigation applies. When multiple rules apply, default to the longest. Do not use for a single ad-hoc "can I delete this file" question — that is a disposition lookup, not a schedule.
