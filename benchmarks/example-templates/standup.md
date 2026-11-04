---
title: Daily standup for {{ project }}
budget_dollars: 0.5
budget_wall_seconds: 300
params:
  - project
---
Produce a one-paragraph standup update for {{ project }}.

Review the last 24 hours of work:
  - Use `read_file` to scan any TODO / NOTES files in the workspace
  - Use `shell` to run `git log --since="24 hours ago" --oneline`
  - Pull recent open questions from the world model via the orchestrator's context

Produce three sections (in this order):
  - **Done yesterday**: 1-3 bullet points
  - **Plan today**: 1-3 bullet points
  - **Blockers**: anything in open_questions, or "none"

End with FINAL: the standup text (plain markdown, no file write).
