---
title: Add a {{ flag }} option to {{ command }}
budget_dollars: 3.0
budget_wall_seconds: 1800
params:
  - flag
  - command
  - behavior
---
Add a `{{ flag }}` option to `{{ command }}` that {{ behavior }}.

Update the CLI help text. Write a test that exercises the new flag.
Don't merge to main -- leave the change uncommitted.

Success criteria:
  - the new flag is wired into the command
  - help text documents the flag
  - a test exercises the flag and passes
  - the change is left uncommitted in the working tree

End with FINAL: a summary of the change and the passing test output.
