---
name: attrition-analysis
triggers:
  - analyze attrition
  - turnover analysis
  - what's driving retention
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Analyzes employee attrition to surface turnover rates, likely drivers, and at-risk segments, producing a driver analysis and a ranked list of segments for retention attention. Output is a draft, descriptive/predictive analysis for People leaders to review; it stages insight, not personnel decisions.

# Steps

1. Define terms and scope: voluntary vs. involuntary, the period, the population, and the denominator for rate. Pull headcount and termination data via `sql_query` from the HRIS; record source and extract date and load into `spreadsheet`.
2. Compute attrition rate overall and sliced by segment (department, level, tenure band, manager, location, role). Annualize correctly and note regrettable vs. non-regrettable where the data supports it.
3. Identify drivers by comparing leaver vs. stayer profiles across available factors (tenure, time-in-role, comp position, engagement scores if present); report associations, and label any predictive/at-risk scoring as a probabilistic signal, not a verdict. Suppress small cells.
4. Rank at-risk segments by combined rate and size (impact), report driver findings with caveats, state assumptions and the data window, and hand off to the People owner — retention actions are theirs to decide.

# Notes

Output is wrong if the rate denominator/annualization is off, voluntary and involuntary are mixed, or association is presented as causation. Predictions are segment-level signals; do not label named individuals as flight risks or feed scores into adverse personnel action — that is an irreversible decision reserved for a human with proper review. Never fabricate driver factors or rates — cite the extract; mark unmeasured drivers unverified. Aggregate and suppress small cells to protect privacy. Not for a single resignation post-mortem — use only for population-level patterns.
