---
name: ml-monitoring-design
triggers:
  - ml monitoring
  - model drift
  - prediction monitoring
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a production monitoring plan for a deployed ML model covering data/feature drift, prediction drift, and downstream quality (when labels arrive), plus alert thresholds and escalation. Produces a concrete monitoring spec naming the metrics, baselines, computation windows, and the action each alert triggers — not a generic "watch for drift" memo.

# Steps

1. Pull the model's real context with knowledge_search: model type (classification/regression/ranking), input features and dtypes, prediction cadence (batch vs online), label latency, and the current serving SLA. Record what you could NOT find — never invent feature names or a baseline that does not exist.
2. Choose drift signals grounded in those features: per-feature distribution drift (PSI or KS for numeric, chi-square/L-infinity for categorical), missing-rate and out-of-range counts, and prediction-score distribution drift. State the reference baseline (training set or a frozen recent production window) and the comparison window (e.g. rolling 24h / daily batch).
3. Define quality monitoring gated on label availability: the primary metric (AUC/PR-AUC/RMSE/etc.) computed once labels land, plus a proxy metric for the label-latency gap (e.g. score calibration, acceptance rate). Note explicitly where you are blind until labels return.
4. Set alert thresholds (warn/critical) per signal, the evaluation window, and the action for each: page on-call, open a retrain ticket, or auto-rollback. Hand off the spec, flag every threshold that is a default needing real-data tuning, and mark retrain/rollback as human-approved (recommend, don't auto-fire).

# Notes

Output is wrong if baselines are assumed rather than confirmed, if thresholds are quoted as production-ready when they are untuned defaults, or if a per-feature alert storm has no aggregation (one upstream schema change trips every feature). Drift is a signal, not a verdict — a drift alert recommends investigation/retrain; it must not auto-retrain or auto-rollback without a human. Do not use this for one-off offline model evaluation (use llm-eval-design or a standard validation report) or for infra/latency monitoring, which is an observability concern, not model monitoring.
