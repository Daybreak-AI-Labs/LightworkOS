---
name: contact-center-forecast
triggers:
  - forecast contact center volume
  - wfm staffing forecast
  - how many agents do we need
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Forecasts contact-center contact volume and translates it into a staffing requirement against a service-level target. Produces a volume forecast by interval, a required-agent (FTE) plan using Erlang-style staffing, and the assumed service level, AHT, and shrinkage so the plan is auditable.

# Steps

1. Pull historical contacts by channel at the planning granularity (daily or interval) for enough history to capture weekly and seasonal patterns via sql_query. Also pull average handle time (AHT) and, if available, occupancy and shrinkage. Report data gaps and any abnormal periods (outages, promos) that should be excluded or flagged, not silently averaged in.
2. Build the volume forecast in the spreadsheet: decompose trend + weekly seasonality (+ known events), project the horizon, and state the method. Mark the forecast as an estimate with the history window it rests on; do not present a single point as certainty — give an expected range where variance is high.
3. Convert volume to staffing per interval: apply AHT and the target service level (e.g. 80% answered in 20s) via Erlang C to get required agents, then gross up for shrinkage (breaks, training, absence) to FTE. Show the inputs for every interval so the math is checkable.
4. Report the volume forecast, required-agents-by-interval, and FTE roll-up against the service-level target. State all assumptions (window, AHT, shrinkage %, SL target, excluded periods) and hand off; recommend a plan — a workforce manager approves rosters and hiring.

# Notes

Output is wrong if abnormal periods are baked into the baseline, if AHT or shrinkage are guessed rather than measured, or if Erlang assumptions (steady-state, single skill, calls queue) are applied to chat/email/blended work without adjustment. Understaffing a tight SL compounds fast — be explicit about the SL target and its sensitivity to AHT. Do not auto-commit schedules or headcount; this stages a recommendation for a human. Not for brand-new queues with no usable history.
