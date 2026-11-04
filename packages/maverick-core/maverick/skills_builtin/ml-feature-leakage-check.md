---
name: ml-feature-leakage-check
triggers:
  - data leakage
  - feature leakage
  - train test leak
tools_needed:
  - pandas_query
  - knowledge_search
---
# What this skill does

Audits a supervised ML pipeline for data leakage — features or splits that let information from outside the training-time horizon (or from the target itself) bleep into the model, inflating offline metrics that collapse in production. Produces a findings report covering target leakage, train/test contamination, and point-in-time correctness. Output is a diagnostic, not a refit.

# Steps

1. Establish the prediction contract: the target, the decision timestamp (what is known at inference time), and the label-availability lag. Everything used as a feature must be knowable strictly before that timestamp. Load the feature table and split definitions with pandas_query.
2. Hunt target leakage: per feature, check correlation/mutual information with the target and flag any near-perfect predictor; inspect for proxies of the label (post-outcome fields, IDs, aggregates computed using the row's own label). Confirm each suspicious column's true availability time rather than assuming it.
3. Check split and preprocessing hygiene with pandas_query: row overlap or duplicate entities across train/test, group leakage (same user/entity in both folds), temporal splits that train on the future, and any scaler/imputer/encoder/target-encoding fit on the full dataset before splitting. Verify aggregations and joins are point-in-time (as-of) and do not pull values dated after the decision timestamp.
4. Report: a leakage findings table (feature/step, leak type, evidence, severity), the point-in-time correctness verdict, and remediation per finding (drop, recompute as-of, refit transforms inside CV). Use knowledge_search for any framework-specific pitfall. State assumptions (claimed availability times you could not verify) and hand off; do not silently mutate the pipeline.

# Notes

The report is wrong if it certifies "no leakage" without confirming feature availability times — an unverified timestamp is the single most common source of phantom accuracy. Group/entity leakage and transforms fit before the split are the most-missed cases; a suspiciously high AUC is a symptom, not proof of either presence or absence. This stages findings for a human — do not drop columns, re-split, or retrain as an irreversible action on your own. Not for unsupervised pipelines or for general model-quality tuning (use a standard validation/calibration pass).
