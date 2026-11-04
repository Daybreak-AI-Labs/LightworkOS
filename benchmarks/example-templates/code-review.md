---
title: Review the most recent commit on {{ branch }}
budget_dollars: 1.0
budget_wall_seconds: 600
params:
  - branch
---
Review the most recent commit on {{ branch }}.

Use `shell` to run `git show HEAD` and inspect the diff. Identify any
logic bugs, missing edge cases, or style issues.

Output a numbered list of findings, each with `file:line` references.
Don't change any code.

End with FINAL: the numbered findings (plain markdown, no file write).
