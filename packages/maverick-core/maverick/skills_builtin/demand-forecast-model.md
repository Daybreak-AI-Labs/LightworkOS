---
name: demand-forecast-model
triggers:
  - demand forecast
  - sales forecast
  - forecasting model
tools_needed:
  - pandas_query
  - spreadsheet
---
# What this skill does

Builds a demand (sales/volume) forecast for a product, family, or location over a stated horizon. Produces a forecast with a quantified accuracy back-test, an explicit baseline comparison, and documented assumptions. Output is a forecast for planning use, not an automatic commitment to inventory or revenue.

# Steps

1. Load and profile the history with pandas_query: actuals by item and period, plus calendar/event/promo/price drivers if available. Confirm grain, bucket, and horizon; check for gaps, stockouts (censored demand, not low demand), outliers, and level shifts, and note how each is treated.
2. Decompose trend, seasonality, and known events; choose a method matched to the data (naive/seasonal-naive baseline, exponential smoothing, or a regression/ML model only if history and drivers justify it). Always compute the seasonal-naive baseline as the bar any model must beat.
3. Back-test honestly with pandas_query using time-series cross-validation (rolling-origin holdout — never a random split, never fit on the future). Report MAPE/WAPE and bias against the baseline per segment; if the model does not beat the baseline, say so and prefer the baseline.
4. Generate the forward forecast in spreadsheet with a prediction interval, by item/period at the planning grain. Report: forecast table, accuracy vs baseline, bias direction, and an assumptions/limitations list (driver availability, demand vs shipments, censoring, structural changes). Hand off for review; do not auto-commit to S&OP, procurement, or financial plans.

# Notes

The forecast is wrong if it is trained or validated with leakage (random split, future drivers, scaler fit pre-split — see ml-feature-leakage-check), if it forecasts constrained shipments while calling it demand, or if it omits a baseline so accuracy looks good in isolation. Stockout periods understate true demand; reconstruct or flag them. A point forecast without intervals overstates certainty — always carry the range. This output is a recommendation: a human reviews and owns the commit into planning systems. Not for ultra-sparse/intermittent items needing Croston-style methods, nor for one-off no-history launches (use analogs/judgment instead).
