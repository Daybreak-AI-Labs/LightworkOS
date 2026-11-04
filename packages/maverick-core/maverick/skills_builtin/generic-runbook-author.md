---
name: generic-runbook-author
triggers:
  - operational runbook
  - runbook author
  - procedure runbook
tools_needed:
  - knowledge_search
---

# What this skill does

Writes an operational runbook for a recurring procedure: preconditions, step-by-step actions, verification, and rollback — usable by someone who isn't the author.

# Steps

1. State the purpose, when to run it, preconditions, and required access/approvals up front. A runbook a stranger can't follow has failed.
2. Write numbered, copy-pasteable steps with the expected result of each, and a verification step that proves success rather than assuming it.
3. Document the failure/rollback path and the escalation contact, plus any irreversible step called out explicitly.
4. Add a post-run checklist and where to record the outcome. State assumptions and hand off.

# Notes

Runbooks fail when steps assume author context, lack verification, or omit rollback. Write for the tired on-call engineer at 3am. Any destructive step needs explicit confirmation and approval — flag it, don't bury it.
