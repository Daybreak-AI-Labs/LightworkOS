---
name: paid-media-plan
triggers:
  - paid media
  - ppc plan
  - media plan
tools_needed:
  - spreadsheet
  - web_search
---
# What this skill does

Plans a paid-media program for a campaign goal and budget: a channel mix with allocated spend, targeting, expected reach/conversions, and KPI targets. Produces a budget-balanced media plan with per-channel targets that a human can approve before any spend is committed.

# Steps

1. Gather inputs: the objective (awareness/leads/sales), total budget, target audience, timeframe, and historical CPA/CPC/CTR benchmarks. Use `web_search` for current platform benchmarks and pricing where internal data is missing — cite each source.
2. Select channels that fit the objective and audience (search, social, display, video, retargeting); reject channels with no audience fit rather than padding the mix.
3. In `spreadsheet`, allocate budget across channels and model expected outcomes (impressions, clicks, conversions, CPA) from the benchmarks. Confirm allocations sum to the total budget and that projected CPA meets the target; flag any channel that misses it.
4. Output the plan as a table (channel, budget, share, targeting, expected conversions, CPA, KPI target) with a pacing note. Report assumptions (benchmark sources, conversion-rate estimates) and hand off for approval before launch.

# Notes

Output is wrong if the channel allocations don't sum to budget, if projections use invented benchmarks instead of cited ones, or if channels are included without audience fit. Benchmarks are estimates — mark them as such; actuals will differ. This is a draft plan: committing spend is irreversible and a human must approve budget and launch. Don't use it for organic/owned channels or for in-flight optimization, which is bid/creative management rather than upfront planning.
