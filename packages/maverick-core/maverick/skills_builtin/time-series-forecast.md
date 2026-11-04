---
name: time-series-forecast
triggers:
  - forecast this metric
  - project the trend forward
  - build a time series forecast
tools_needed:
  - pandas_query
  - spreadsheet
---
# What this skill does

Projects a single historical metric (revenue, signups, demand, etc.) forward over a stated horizon, producing a point forecast, prediction intervals, and a backtest error estimate so the consumer knows how much to trust it. Handles univariate series with regular cadence and optional seasonality; it does not do multivariate causal modeling.

# Steps

1. Load the actual series via `pandas_query` or `spreadsheet`. Confirm the time column parses to dates, the cadence is regular (daily/weekly/monthly), and there are no duplicate or missing periods — reindex and flag gaps rather than silently interpolating. Record the series length; refuse to forecast if you have fewer than ~2 full seasonal cycles.
2. Inspect for trend, seasonality, and level shifts (plot or describe rolling mean/std). Choose the simplest adequate method: naive/seasonal-naive baseline, then an additive method (e.g., exponential smoothing / Holt-Winters) only if seasonality or trend is clearly present. State the chosen model and why.
3. Backtest with a rolling/expanding-origin split: fit on history up to cutoff, predict the held-out tail, and compute error (MAPE or sMAPE, plus MAE in native units) against the naive baseline. If the model does not beat the baseline, fall back to the baseline.
4. Refit on the full series, generate the point forecast and prediction intervals (e.g., 80/95%) over the requested horizon, and report the table plus backtest error, the model used, and assumptions (cadence, seasonal period, treatment of gaps). State that intervals widen with horizon and that the forecast assumes no regime change.

# Notes

Output is wrong when: the series has a structural break the model can't see, the horizon exceeds what history supports, or gaps were interpolated as if real. Always report backtest error alongside the forecast — a point forecast without an interval or error is misleading. Mark the forecast as a projection, not a commitment; decisions with irreversible consequences (capacity buys, hiring) are recommendations for a human to ratify. Do not use for event-driven series dominated by one-off shocks, or when the driver of interest is an external variable (use a causal/regression approach instead).
