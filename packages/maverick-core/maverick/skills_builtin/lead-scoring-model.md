---
name: lead-scoring-model
triggers:
  - lead scoring
  - prioritize leads
  - mql model
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Builds a transparent lead-scoring model that ranks inbound leads by fit (how well they match the ideal customer profile) and intent (observed buying behavior). Produces weighted fit/intent factors, point values, and MQL/SQL thresholds calibrated against historical conversion. The output is a scoring rubric sales and marketing ops apply to route and prioritize leads.

# Steps

1. Pull historical lead and outcome data with `sql_query`: firmographics (industry, employee count, region), source channel, engagement events (page views, content downloads, demo requests, email replies), and the converted/won flag. Confirm the date window and minimum sample size; if conversions are too sparse to calibrate, flag it and fall back to expert weights, labeled as unvalidated.
2. Separate factors into fit (firmographic ICP match) and intent (behavioral signals). For each factor, measure lift — conversion rate of leads with the signal vs. baseline — using `sql_query` or a `spreadsheet` pivot. Cite the observed rates; do not assign weights without supporting data or an explicit stated assumption.
3. Assign point values proportional to measured lift, normalize fit and intent to comparable scales, and combine (e.g., a fit x intent grid or weighted sum). Set MQL/SQL thresholds by back-testing: pick cutoffs that capture most won deals while keeping volume handleable, and report the resulting precision/recall trade-off.
4. Deliver the model in a `spreadsheet`: factor table with weights, the scoring formula, threshold tiers (A/B/C or MQL/SQL), and a back-test summary on a holdout period. Report the calibration window, sample size, and assumptions, and hand off to revenue ops for review before activation.

# Notes

Output is wrong if weights come from intuition presented as data, if it leaks the outcome variable into the features, or if thresholds are tuned on the same data used to fit them (overfitting). Model is a recommendation: a human owner approves it before it routes real leads or triggers outreach, and re-scoring existing pipeline is staged, not auto-applied. Mark any weight not backed by measured lift as an assumption. Do not use when there is no outcome history at all (cold start) or for individual one-off lead judgments.
