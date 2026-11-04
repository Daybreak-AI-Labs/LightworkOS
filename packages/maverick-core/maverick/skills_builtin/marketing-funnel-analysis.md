---
name: marketing-funnel-analysis
triggers:
  - analyze the marketing funnel
  - funnel analysis
  - where are we losing conversions
  - stage conversion rates
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Diagnoses a marketing/demand funnel by measuring stage-to-stage conversion and surfacing where prospects leak. Produces a funnel table (counts and conversion rate per stage), identifies the worst-performing transitions against a baseline, and segments leaks by source/campaign/cohort so the drop is actionable rather than just observed.

# Steps

1. Define the stage sequence from real lifecycle data (e.g. visitor -> lead -> MQL -> SQL -> opportunity -> closed-won) with `sql_query`. Confirm each stage has an unambiguous timestamped event and that stages are strictly ordered; state the time window and whether you are counting cohorts (entered-in-period) or a snapshot.
2. Count entities at each stage and compute stage-to-stage conversion rate and overall funnel conversion. Use cohort logic so a lead created last month and converted this month is not double-counted or dropped — flag if the data only supports a snapshot approximation.
3. Rank the transitions by conversion rate and by absolute volume lost; the biggest leak is usually not the lowest rate but rate x volume. In the `spreadsheet`, segment the worst transitions by source, campaign, and lead cohort to see whether the leak is concentrated or systemic.
4. Report the funnel table, the top leaks with their segment breakdown, and stage-velocity (time between stages) where available. State assumptions (window, cohort vs snapshot, stage definitions) and hand off prioritized hypotheses; recommend follow-up tests rather than asserting root cause.

# Notes

Output misleads if stages overlap or skip (an entity jumping straight to SQL inflates that transition), if the window is shorter than the sales cycle (in-flight deals look like leaks), or if snapshot counts are presented as cohort conversion. Low-volume stages produce noisy rates — annotate small denominators. The analysis locates where loss happens, not why; root cause is a hypothesis for testing, not a conclusion. Do not use when stage data is unreliable or self-reported without timestamps. No data is modified; this is read-only diagnosis.
