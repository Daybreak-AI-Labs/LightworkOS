---
title: Migrate {{ library }} from {{ old_version }} to {{ new_version }}
budget_dollars: 3.0
budget_wall_seconds: 1800
params:
  - library
  - old_version
  - new_version
---
We're on {{ library }}=={{ old_version }}. The latest is {{ new_version }}.

Read the changelog, identify breaking changes, plan the migration as a
checklist, and apply non-breaking changes now. Stop and ask before any
breaking change.

Success criteria:
  - a migration checklist covering every breaking change
  - non-breaking changes applied and verified against the test suite
  - any breaking change surfaced as a question, not applied

End with FINAL: the checklist and a summary of what was applied.
