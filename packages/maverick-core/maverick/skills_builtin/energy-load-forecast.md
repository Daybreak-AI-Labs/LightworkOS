---
name: energy-load-forecast
triggers:
  - load forecast
  - demand forecast
  - peak load
tools_needed:
  - pandas_query
  - spreadsheet
---
# What this skill does

Produces a weather-normalized electric (or gas) load forecast for a service territory or feeder over a stated horizon. Output is a time-indexed forecast series plus identified system and coincident peaks, with normalized vs. actual load separated so planners can size capacity and bid into markets.

# Steps

1. Load historical interval load (hourly/15-min) and the matching weather series (temperature, humidity, optionally wind/cloud) for the same territory and period via pandas_query; confirm timezones align and there are no gaps — flag any imputed intervals.
2. Build the normalization model: regress load on heating/cooling degree days (or a temperature spline) plus calendar effects (hour-of-day, day-of-week, holidays). Report fit (R^2, MAPE on a holdout) so the user can judge reliability.
3. Apply normal weather (typically a 10-30 year TMY or rolling normal) to the fitted model to generate the weather-normalized forecast; produce the actual-weather forecast separately when a near-term scenario is requested.
4. Extract system peak and the time of coincident peak per period (monthly/seasonal), tabulate in spreadsheet alongside reserve-margin context, and hand off the forecast with the normalization basis, weather-normal vintage, holdout error, and any data-gap assumptions stated.

# Notes

Wrong when the weather normal is mismatched to the load history, holidays/DST are unhandled, or load growth (EVs, electrification, large new interconnects) is omitted — the model extrapolates the past and will understate future peaks. Always mark the forecast as a planning estimate, not a dispatch commitment; market bids and capacity procurement based on it are decisions a human planner owns. Do not use for sub-feeder or single-customer forecasting without behind-the-meter (DER/solar) data — net load behaves differently.
