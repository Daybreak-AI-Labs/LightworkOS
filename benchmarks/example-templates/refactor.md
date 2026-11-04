---
title: Refactor {{ target }} into smaller units
budget_dollars: 3.0
budget_wall_seconds: 1800
params:
  - target
---
Refactor {{ target }} into smaller, testable units. Preserve behavior.

Add tests covering each split. Use `shell` to run the test suite and
verify nothing regressed.

Success criteria:
  - the function is split into smaller named units
  - each split has at least one test
  - the full test suite passes after the change

End with FINAL: a summary of the split and the passing test output.
