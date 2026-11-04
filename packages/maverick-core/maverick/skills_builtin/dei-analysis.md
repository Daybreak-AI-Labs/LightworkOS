---
name: dei-analysis
triggers:
  - run a dei analysis
  - diversity metrics for the org
  - representation breakdown
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Analyzes workforce diversity and inclusion metrics across the employee lifecycle, producing representation breakdowns, gap findings against benchmarks, and prioritized observations. Output is a draft analysis for People/DEI leaders to review; it informs decisions but does not make them.

# Steps

1. Confirm scope and dimensions (gender, ethnicity, age band, etc.), the population, the time window, and any benchmark or goal. Pull data via `sql_query` from the HRIS; record source table/extract date and load into `spreadsheet` for shaping.
2. Compute representation by dimension across stages — overall headcount, by level/seniority, hires, promotions, and exits — so you can see where representation thins (e.g. drops at senior levels). Suppress or aggregate any cell below the agreed small-count threshold to protect privacy.
3. Compare each metric to its benchmark/goal and quantify gaps (percentage points and direction). Identify the largest gaps and any stage where representation degrades through the pipeline.
4. Report representation tables, gap findings, and the small-count/privacy caveats. State the data window and assumptions, do not infer causation from correlation, and hand off to the DEI/People owner for decisions.

# Notes

Output is wrong if small groups are exposed below the suppression threshold, if self-ID coverage gaps are ignored (missing/undisclosed inflates or hides gaps), or if gaps are read as causes. Never fabricate counts or benchmarks — cite the extract and source; mark missing benchmarks unverified. Sensitive PII: aggregate, suppress small cells, and never surface individuals. The skill describes and recommends; targets, programs, and any individual action are human decisions. Not for individual pay-equity case review — that needs a controlled, legally-reviewed process.
