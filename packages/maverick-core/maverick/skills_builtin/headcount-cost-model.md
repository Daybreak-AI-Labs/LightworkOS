---
name: headcount-cost-model
triggers:
  - headcount model
  - people cost
  - fully loaded cost
tools_needed:
  - spreadsheet
---
# What this skill does

Builds a fully-loaded headcount cost model from a role roster: base salary plus benefits, payroll taxes, bonus, equity, and overhead, phased by each hire's start month. Produces a per-role, per-month cost schedule that rolls up to a monthly and annual people-cost line for budgeting and runway analysis.

# Steps

1. Gather the role roster from the source the user provides (existing plan tab, HRIS export, or stated headcount plan): role title, level, base salary, planned start month, and FTE fraction. Do not invent salaries — if base is missing, flag the role and request a band or a benchmark.
2. Establish the loading factors as named assumptions: employer payroll tax %, benefits %, bonus target %, equity/SBC %, and per-head overhead (software, facilities, recruiting amortization). Pull each from the user, policy doc, or a cited benchmark; mark any guessed value as unverified.
3. In the spreadsheet, compute fully-loaded cost per role = base x FTE x (1 + payroll% + benefits% + bonus% + equity%) + overhead, then spread it across months from start month forward (zero before start, partial month if mid-month, ramp if specified).
4. Roll up to monthly and annual totals by department and in aggregate, add a sensitivity row (loading factor +/- 5pts), and hand off the model. State every assumption inline and flag roles with placeholder salaries as needing sign-off.

# Notes

Output is wrong if start-month phasing is ignored (a Q4 hire booked as full-year cost overstates spend) or if equity/SBC is double-counted against a separate cash budget — confirm cash vs total-cost intent. Loading factors vary by geography and benefits plan; never reuse one company's factors for another without saying so. This is a draft model for planning; actual offer amounts, tax rates, and headcount approvals are decided by Finance/HR — do not treat projected costs as committed spend. Do not use for individual compensation decisions or anything requiring real per-person PII.
