---
name: model-risk-validation
triggers:
  - validate this model for model risk
  - run an SR 11-7 model validation
  - model risk management review
tools_needed:
  - knowledge_search
  - pandas_query
---
# What this skill does

Performs an independent validation of a quantitative or ML model under a model-risk-management framework (e.g. SR 11-7 / OCC 2011-12). Produces a validation report covering conceptual soundness, data and assumptions, outcomes analysis (back-testing, benchmarking, sensitivity), and ongoing-monitoring findings, with a residual-risk rating and remediation items. Output is a recommendation for the validator/MRM committee, not an approval.

# Steps

1. Pull the model's authoritative artifacts via knowledge_search: model development document, data lineage, prior validations, and applicable policy (cite each source and date; mark any missing artifact as a gap, do not infer its contents).
2. Assess conceptual soundness: confirm the methodology fits the stated use, list every material assumption and limitation, and check that variable selection and theory are documented and defensible. Flag undocumented choices as findings.
3. Run outcomes analysis with pandas_query on the supplied datasets: back-test predictions vs. actuals, benchmark against a challenger or champion model, and run sensitivity/stability tests across segments and time. Record metrics, sample sizes, and any data-quality caveats; never fabricate results for data you were not given.
4. Review ongoing monitoring (thresholds, triggers, escalation) and data quality controls, then compile the report with per-section findings, severity, a residual-risk rating, and remediation owners/dates. End by stating assumptions and handing off to the validator/MRM committee for the approve/restrict/reject decision.

# Notes

Output is wrong if metrics are reported without their sample size, test window, or data-quality caveats, or if a missing artifact is silently treated as compliant. Conceptual soundness and outcomes analysis are both required — a model that back-tests well but lacks documented assumptions is still a finding. Validation must be independent of development; if the same agent/team built the model, escalate the conflict rather than self-validating. This skill recommends a rating and remediation only — the use/restrict/reject decision and any production change is an irreversible action reserved for a human approver. Do not use for qualitative or non-model tools, or where no development documentation and no outcomes data exist (escalate as un-validatable).
