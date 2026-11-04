---
title: Reproduce and diagnose a bug
budget_dollars: 2.0
budget_wall_seconds: 1200
params:
  - report
---
We have a bug report: "{{ report }}".

Reproduce it by writing the smallest failing test, then propose a fix.
Don't apply the fix yet -- show the diff.

Success criteria:
  - a new failing test that reproduces the reported behavior
  - the test fails for the stated reason (not an unrelated error)
  - a proposed diff that would make the test pass

End with FINAL: the failing test and the proposed diff.
