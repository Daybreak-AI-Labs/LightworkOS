---
name: feature-store-design
triggers:
  - feature engineering
  - feature store
  - design ml features
tools_needed:
  - knowledge_search
---
# What this skill does

Designs the ML features and the feature-store layout for a given prediction target. Takes the modeling goal and available source data, then produces feature definitions with their entities, transformations, freshness/SLA, and an offline/online serving plan built for reuse across teams. Output is a feature design doc: a feature table per entity with point-in-time-correct definitions and ownership.

# Steps

1. Clarify the prediction target, the entity (user, account, session), and the prediction-time cutoff. Use `knowledge_search` to find existing features for the same entity in the feature store or prior model docs — reuse before inventing, and cite what you found.
2. For each candidate feature, write a definition: source table(s), transformation, aggregation window, and the entity key. Make every feature point-in-time correct — it must be computable using only data available before the label timestamp, or it leaks.
3. Specify freshness and serving for each feature: batch vs streaming, materialization cadence, online-store TTL, and the SLA the model depends on. Note which features are shared (catalog-level, owned centrally) vs model-specific.
4. Assemble the design doc — feature tables grouped by entity, with owners, freshness, lineage to source, and a backfill plan — and report it, stating assumptions about source availability and which definitions are unverified pending a data audit.

# Notes

The design is wrong if a feature uses post-label information (train/serve leakage) or if offline training features are computed differently from the online serving path (training-serving skew) — call out any definition that can't be served identically in both. Flag features built on low-freshness sources that the model assumes are real-time. Recommend definitions; a human and a data audit confirm source semantics before materialization. Do NOT use to design the model architecture or the label itself — this covers inputs only.
