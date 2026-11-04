---
title: Write tests for uncovered code in {{ project }}
budget_dollars: 3.0
budget_wall_seconds: 1800
params:
  - project
---
Find a file in {{ project }} with low test coverage. Use `shell` to run
coverage.py to identify candidates.

Write tests covering the missing branches. Aim to push coverage on that
file to >=80%.

Success criteria:
  - a low-coverage file is identified with its current percentage
  - new tests cover the missing branches
  - coverage on that file reaches >=80%
  - the full test suite still passes

End with FINAL: the file chosen, before/after coverage, and the new tests.
