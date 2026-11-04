---
name: feature-pit-correctness-check
triggers:
  - check feature leakage
  - point in time join
  - train serve skew
  - feature correctness audit
tools_needed:
  - read_file
  - sql_query
---
# What this skill does

This skill audits a machine-learning feature pipeline for the two failures that quietly destroy model validity: label leakage (a feature that encodes the target or uses information unavailable at prediction time) and train/serve skew (the offline feature computation differing from the online one). It checks that historical feature values are reconstructed with point-in-time-correct joins — each feature as it would have been known at the prediction timestamp, not as-of today — and compares offline vs serving logic. The output is an audit report listing offending features with evidence; it does not modify the pipeline, retrain, or change any feature definition.

# Steps

1. Use read_file to read the feature definitions and both the offline (training) and online (serving) computation code, and to identify the prediction timestamp / label timestamp for each training example (when the prediction is made vs when the outcome is known).
2. For each feature, use sql_query to check point-in-time correctness: confirm the training join uses the feature value as-of the prediction time (an as-of join keyed on event time), not the latest value. Flag any feature joined without a time bound, or computed from data timestamped after the prediction time, as leakage.
3. Test for label leakage directly: flag features suspiciously correlated with the target, derived from post-outcome data, or that are transformations of the label; and check for train/serve skew by comparing the offline and online formulas, default/null handling, and aggregation windows for each feature.
4. Assemble the audit report: per feature, a verdict (clean / leakage / skew-risk) with the evidence (the offending join, the timestamp violation, the formula diff, or the suspicious correlation), and a prioritized list of features to fix. Stage it for the ML/data team. Mark that fixing definitions and retraining are human steps.

# Notes

Point-in-time correctness is the crux: training on a feature's current value when serving will only ever see its value at prediction time is leakage that inflates offline metrics and collapses in production — verify every historical join is bounded by the prediction timestamp. A feature that is "too predictive" is a red flag, not a win; trace it back, because it is usually leaking the label. Train/serve skew is subtler — the same feature computed two ways (different default for nulls, different window) silently degrades the live model; diff the offline and online logic, don't assume they match. This skill audits and reports; it does not edit feature definitions, remove features, or retrain — those are human decisions on the evidence. When a join lacks any event-time key, treat it as leakage until proven otherwise.
