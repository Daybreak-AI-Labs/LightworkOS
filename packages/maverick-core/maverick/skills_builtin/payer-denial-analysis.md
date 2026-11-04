---
name: payer-denial-analysis
triggers:
  - analyze claim denials
  - run a denial analysis
  - reduce claim denials
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Analyzes a population of denied/rejected claims to find root causes and produce a prevention plan. Produces a root-cause breakdown by denial category (CARC/RARC), payer, service line, and dollars at risk, with targeted prevention actions and a recovery (appeal) shortlist. It diagnoses and recommends; it does not submit appeals or write off balances.

# Steps

1. Define scope: date range, payers, claim/denial population, and whether the goal is recovery (appeal the existing denials), prevention (stop future ones), or both. Confirm which fields carry denial reason codes.
2. Pull denials with `sql_query` — CARC/RARC codes, payer, CPT/DRG, billed/denied amount, denial date, location/provider — and load into `spreadsheet` to categorize (eligibility, authorization, coding, timely filing, medical necessity, duplicate). Validate totals against the source.
3. Quantify each category by count, dollars, and denial rate; rank by impact and by preventability. For the top categories, trace the upstream process step that produced the error (front-desk eligibility, auth capture, coding, claim edits).
4. Deliver a root-cause analysis with prevention actions mapped to each category and owner, plus an appeal shortlist (high-dollar, recoverable, within filing window). Hand off to RCM leadership; state assumptions and flag any denials with missing/ambiguous reason codes as unclassified.

# Notes

Wrong output looks like: grouping by raw code instead of root cause, double-counting resubmissions as new denials, mixing recoverable denials with true non-covered write-offs, or ignoring the timely-filing window. Numbers must reconcile to the source query — report unclassified volume rather than forcing a bucket. Safety boundary: appeals, payer outreach, and write-offs are staged recommendations a human in RCM executes; the skill never submits, adjusts, or closes a claim. Do not use as a substitute for a coding audit on coding-specific denials.
