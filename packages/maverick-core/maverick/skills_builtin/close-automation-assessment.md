---
name: close-automation-assessment
triggers:
  - close automation
  - automate the close
  - close acceleration
  - speed up month-end
tools_needed:
  - knowledge_search
---
# What this skill does

Assesses an organization's period-end close to find steps worth automating, producing a ranked candidate list with effort, risk, and ROI estimates. Output is an assessment a finance leader uses to prioritize an automation backlog — not an implementation.

# Steps

1. Reconstruct the current close from real artifacts via `knowledge_search`: the close checklist/calendar, owners, durations, and dependencies per task. If a documented checklist doesn't exist, list the gap explicitly rather than inventing tasks.
2. Tag each task by automatability signal: high-volume/repetitive, rules-based, system-to-system data movement (good candidates) vs. judgmental/estimate-driven steps (poor candidates, keep human-owned). Note which tags are confirmed from the artifact vs. inferred.
3. For each candidate estimate effort (low/med/high), residual control risk, and benefit (hours saved per close x periods/year, days off the critical path). Compute a simple ROI/priority score; cite the duration source for each.
4. Rank candidates, separate quick wins from larger builds, and report the top recommendations with assumptions stated. Hand off the assessment for human prioritization — recommend, do not schedule or change any close process.

# Notes

Wrong if it automates judgmental steps (accruals, valuation, reserves) — those need human review and automating them creates control risk. Also wrong if hours-saved figures aren't traceable to a cited duration source. This is a diagnostic deliverable only; it does not build automations or alter the close calendar. Not for a single recurring journal entry already known to be automatable — that's a task ticket, not an assessment.
