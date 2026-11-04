---
name: pipeline-forecast-readout
triggers:
  - produce a pipeline forecast for the quarter
  - sales forecast readout for the review
  - what's our commit and best case
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Turns the live opportunity pipeline into a defensible period forecast: a commit number, a best-case number, weighted/expected value, pipeline-coverage ratio against quota, and the deals and assumptions that drive each. Produces a forecast readout suitable for a sales review, with explicit risks and the data cutoff. It reports a forecast; it does not change deal stages or quotas.

# Steps

1. Pull open and recently-closed opportunities with `sql_query`: opp_id, owner, amount, stage, probability, forecast_category (commit/best-case/pipeline/omitted), close_date, last_activity_date, created_date. Note the snapshot timestamp — every number is "as of" that moment.
2. Scope to the forecast period by close_date and validate hygiene: flag deals with close dates in the past, stale last_activity (e.g. >30 days), missing amounts, or probability that contradicts stage. Quarantine or annotate dirty rows rather than dropping them silently.
3. In `spreadsheet`, compute the readout: commit = sum of commit-category deals; best-case = commit + best-case category; expected = Σ(amount × probability); coverage = total open pipeline ÷ remaining quota gap. Break out by segment/rep where the review needs it, and identify the top deals that swing the number.
4. Deliver the readout — commit / best-case / expected / coverage plus the risk list (slipping close dates, stale deals, single-deal concentration, category vs. probability mismatches) — and state the snapshot time and every assumption (probability source, coverage benchmark). Hand off as analysis for the forecast call; the rep/manager owns the called number.

# Notes

The forecast is wrong if it inherits dirty CRM data uncritically — past-due close dates and stale activity inflate commit; report hygiene exceptions alongside the totals. Distinguish category-based commit (what reps called) from probability-weighted expected value (what the math says) and never silently substitute one for the other. Coverage is meaningless without a stated quota/gap benchmark — cite it. This is a decision-support readout: changing forecast categories, deal stages, or quota in the CRM is a human action. Do not use when the pipeline is empty, the period is undefined, or probability fields are unpopulated — there is nothing to weight.
