---
name: month-end-close-checklist
triggers:
  - month end close
  - close checklist
  - close the books
tools_needed:
  - spreadsheet
  - sql_query
---
# What this skill does

Runs a disciplined month-end close for a specified entity and period, producing a sequenced close checklist with task owners, dependency ordering, control ties (subledger-to-GL, bank, intercompany), and explicit review gates. Output is a tracked checklist that shows what is done, what is blocked, and what still needs a reviewer sign-off before the books are declared closed.

# Steps

1. Confirm the scope from real inputs: entity/legal entities, period (month + fiscal year), close calendar target date, and the GL system of record. Pull the prior-period close checklist (read it via spreadsheet) as the baseline so no recurring task is dropped; flag any task with no current owner.
2. Build the task list grouped by close phase — subledger cutoffs (AP/AR/payroll/revenue), accruals and estimates, intercompany, reconciliations, allocations/eliminations, flux review, reporting — and order them by dependency (e.g., subledgers must post before recons; recons before flux). Assign each task an owner and a target day-of-close.
3. Run the control ties with sql_query against the GL and subledgers: subledger control totals vs GL balances, bank statement vs GL cash, intercompany elimination nets to zero, trial balance debits = credits. Mark each tie pass/fail with the queried amounts; do not assert a tie is clean without the supporting numbers.
4. Insert review gates: each phase needs a named preparer and an independent reviewer before downstream tasks unblock; the final close gate requires controller sign-off. Report the checklist with status per task (done/in-progress/blocked), outstanding ties, and the gates still awaiting sign-off. State assumptions (e.g., FX rates as of period-end pulled from source X) and stage the "books closed" declaration for a human — do not declare close complete yourself.

# Notes

Output is wrong if a tie is marked clean without the queried amounts behind it, if tasks are listed out of dependency order (recons before subledgers post), or if the prior-period baseline was ignored and a recurring accrual/allocation was missed. The close declaration and any GL posting are irreversible-adjacent — this skill prepares and recommends; the controller signs off. Cite the GL/subledger source and timestamp for every tie; mark any balance you could not query as unverified. Do not use for ad-hoc one-off reconciliations (use account-reconciliation) or for explaining movements (use flux-analysis).
