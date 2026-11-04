---
name: attribution-model-build
triggers:
  - build an attribution model
  - marketing attribution
  - which channels deserve credit
  - channel credit and ROI
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Builds a marketing-attribution view from touchpoint and conversion data: assigns conversion credit across channels under multiple models (first-touch, last-touch, linear, time-decay, position-based) and ties credited conversions back to spend to produce per-channel ROI. Produces a model-comparison table plus a recommended view, so stakeholders see how channel value shifts by methodology rather than trusting a single default.

# Steps

1. Pull the raw touchpoint stream with `sql_query`: one row per (user/lead id, channel, campaign, touch timestamp) joined to converters and conversion value/timestamp. Confirm the join key is real (no synthetic surrogate) and record the lookback window and conversion event you used — state both explicitly.
2. Validate the data before modeling: count converters with zero touchpoints (attribution gap), touchpoints after the conversion timestamp (clock/timezone error), and duplicate touches. Drop or flag these; never silently impute missing touches.
3. Compute credit per model in the `spreadsheet`: first-touch (100% to first), last-touch (100% to last), linear (even split), time-decay (weight by recency to conversion), position-based (40/20/40). Aggregate credited conversions and credited value by channel for each model.
4. Join channel spend to credited value to get cost-per-conversion and ROAS per channel per model. Build a model-comparison matrix (channels x models) highlighting where rank order disagrees, and report it with the lookback/conversion-event assumptions stated. Recommend a model but flag that the choice is a business decision; do not reallocate budget automatically.

# Notes

Output is wrong if the touchpoint stream is incomplete (offline/dark-social touches absent), if spend is not aligned to the same channel taxonomy as touches, or if the lookback window truncates long sales cycles. Multi-touch models are unreliable below a few hundred conversions — note low-sample channels rather than reporting noisy ROAS. Attribution is correlational, not causal; recommend incrementality testing before large reallocation. This is a draft analysis — a human owns budget decisions. Do not use for single-touch businesses (one channel, no journey) where last-touch is trivially correct.
