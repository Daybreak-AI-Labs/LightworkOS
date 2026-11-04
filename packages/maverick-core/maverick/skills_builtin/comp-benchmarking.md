---
name: comp-benchmarking
triggers:
  - benchmark this role against the market
  - is our pay competitive
  - get market pay data for these jobs
tools_needed:
  - web_search
  - spreadsheet
---
# What this skill does

Benchmarks pay for one or more roles against the external market by gathering market salary data, normalizing it to comparable cuts (geography, level, industry), and placing current pay against market percentiles. Produces a comp benchmark showing market P25/P50/P75 per role and where each incumbent or range sits (compa-ratio / percentile placement).

# Steps

1. Define the benchmark scope per role: a clear job match (level and scope, not just title), the relevant labor market (geography and industry peer set), and the pay elements in scope (base, total cash, or total comp). Pull current internal pay for the comparison.
2. Gather market data via `web_search` from named, dated sources (published surveys, compensation databases, government wage data, reputable aggregators). Record the source, effective date, and sample basis for every data point; cite each one. Mark any figure you could not corroborate from a second source as unverified — never fabricate a percentile.
3. In a `spreadsheet`, normalize each source to a common cut (same geo, level, and pay element; age-adjust stale data forward to a common effective date), then derive market P25/P50/P75 per role. Compute placement: current pay vs market median (compa-ratio to P50) and which percentile band each role/incumbent falls in.
4. Report the benchmark table — market percentiles per role plus current placement and any roles materially below or above market — with sources and effective dates cited inline. State the job-match basis, market definition, and aging assumptions. Present as advisory; pay changes are a human/comp-committee decision.

# Notes

The output is wrong if roles are matched by title alone (a "Manager" at one company is an IC level at another — match on scope/level) or if sources are blended across mismatched geographies/industries without normalization. Always cite source and effective date and age stale data to a common point; an undated median is unusable. A thin sample (one survey, small n) is a weak benchmark — say so rather than implying false precision. Do not state percentiles you cannot source. Not for designing pay ranges or merit budgets from scratch (that is range architecture) and not a substitute for a licensed survey where one is contractually required.
