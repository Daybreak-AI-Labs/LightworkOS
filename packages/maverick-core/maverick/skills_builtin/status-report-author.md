---
name: status-report-author
triggers:
  - status report
  - project update
  - rag status
tools_needed:
  - knowledge_search
---
# What this skill does

Compiles a concise project status report for stakeholders on a recurring cadence. Produces a report with an overall RAG (Red/Amber/Green) call, progress since the last update, active risks and issues, and explicit asks — so a reader knows in one glance whether the project is on track and what is needed from them.

# Steps

1. Pull current state with `knowledge_search`: the project plan or milestones, the previous status report, and any logged risks, blockers, or metrics. Establish the reporting period (since last report).
2. Set the overall RAG and justify it in one line: Green = on track, Amber = at-risk with a recovery plan, Red = off-track needing intervention. Make the color follow the evidence, not optimism.
3. Fill the body: Progress (what completed this period, against plan), Risks/Issues (each with impact and a mitigation or owner), Upcoming (next period's milestones), and Asks (specific decisions, resources, or unblocks needed).
4. Tie each status claim to a source (milestone, metric, ticket); mark anything you could not confirm as `[unverified]`. Hand off the report, stating the RAG rationale and any assumption behind a date or percentage.

# Notes

The report is wrong if the RAG color contradicts the listed risks (e.g. Green with an unmitigated Red risk), or if "Asks" is empty when the project is blocked. Do not soften a Red to avoid alarm or invent progress to fill the period — a truthful Amber with a recovery plan is the goal. This drafts a status; the project owner approves the RAG call before it goes to stakeholders. Not for post-mortems or detailed plans — keep it to the period's signal.
