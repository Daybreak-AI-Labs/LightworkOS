---
name: sales-pipeline-hygiene
triggers:
  - pipeline hygiene
  - crm hygiene
  - stale opportunities
tools_needed:
  - sql_query
---
# What this skill does

Audits open-pipeline data quality against hygiene rules and produces a prioritized list of records to fix: stale opportunities, missing required fields, past-due close dates, and stage/amount inconsistencies. Output is a cleanup worklist scoped to one team or segment, ready for a human to action in the CRM.

# Steps

1. Query open opportunities with sql_query for the target scope: id, owner, stage, amount, close date, last-activity date, next-step, and required fields per the org's data standard. Record the snapshot timestamp and the row count audited.
2. Apply hygiene checks per record: close date in the past, no activity beyond the staleness threshold, empty required fields (amount, next-step, close date), amount of zero/null at a late stage, and stage older than its expected dwell time. Cite the threshold each rule uses.
3. Categorize and prioritize findings by impact (e.g., late-stage stale deals first) and by owner, and quantify the dollar amount and deal count behind each issue type.
4. Report a worklist grouped by owner with record id, violation, and recommended fix (update field / re-date / close-lost / re-stage); state assumptions (thresholds, scope) and hand off to reps or RevOps. Do not modify or close any record yourself.

# Notes

The audit is wrong if thresholds don't match the org's documented standard — always cite the rule source and don't invent staleness windows. A flagged record is a candidate, not a verdict; closing-lost or deleting an opportunity is irreversible and stays with the owner/RevOps. Avoid auto-actioning bulk updates. Do not use this skill to evaluate forecast accuracy or rep performance — it audits data quality only, not deal merit.
