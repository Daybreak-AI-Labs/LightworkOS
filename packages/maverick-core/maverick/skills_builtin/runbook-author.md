---
name: runbook-author
triggers:
  - write a runbook for this procedure
  - document this operational process for on-call
  - on-call doc for this alert
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Produces an operational runbook an on-call engineer can execute under pressure: a procedure with clear trigger conditions, exact step-by-step actions, a verification check that confirms recovery, and a rollback for when a step makes things worse. The output is precise and copy-pasteable so an unfamiliar responder can run it at 3am.

# Steps

1. Gather the real procedure: read existing scripts, alert definitions, dashboards, and prior incident notes via read_file and knowledge_search. Identify the exact trigger (which alert/symptom fires this runbook) and the preconditions/access required. Use real command names, paths, and dashboard links — do not invent them; mark anything you could not confirm as unverified.
2. Write Triggers and Prechecks: the symptom or alert that starts this runbook, severity, who to page, and what to check first to confirm you are in the right scenario (and not a look-alike).
3. Write Steps as numbered, literal actions with exact commands/queries and the expected output of each; after the fix, add a Verification section with a concrete check (metric returns to baseline, health endpoint green) that proves recovery — not just "looks fine".
4. Add Rollback (how to safely undo each mutating step), escalation path, and links to logs/dashboards; assemble the runbook, flag destructive steps explicitly, state assumptions, and hand off for review by the owning team. Do not mark it as validated until someone has run it in a drill.

# Notes

A runbook is wrong when it lacks a verification step (responder thinks they fixed it and didn't), when commands are paraphrased instead of literal, or when a mutating action has no rollback. Destructive or irreversible commands (restarts, failovers, deletes, scaling to zero) must be called out and gated on human judgment with explicit blast-radius notes — the runbook recommends and stages them, it does not auto-run them. Keep it current: a runbook that drifts from reality is worse than none. Not for one-time setup or for design decisions (use an RFC).
