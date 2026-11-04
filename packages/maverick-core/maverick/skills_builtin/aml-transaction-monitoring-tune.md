---
name: aml-transaction-monitoring-tune
triggers:
  - aml tuning
  - transaction monitoring
  - alert thresholds
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Tunes the thresholds of AML transaction-monitoring (TM) scenarios by quantifying the trade-off between alert volume and detection effectiveness across a candidate threshold range. Produces an above-the-line / below-the-line (ATL/BTL) analysis showing alert rate, productivity (SAR/escalation yield), and missed-risk exposure per threshold, so a BSA analyst can recommend a setting. Output is an analysis to support a tuning decision, not an applied configuration change.

# Steps

1. Pull the production data for the scenario being tuned via `sql_query` — historical alerts with disposition (closed, escalated, SAR-filed) and the raw transaction population the scenario scores — over a stated lookback window; record row counts and date range so the sample is auditable. Never fabricate dispositions; if outcome labels are missing, stop and report that productivity cannot be measured.
2. For each candidate threshold in a defined sweep (including the current value and BTL samples below it), compute in `spreadsheet`/SQL: alerts generated, alert rate per 1,000 accounts/txns, true-positive proxy (escalations or SARs that would still trigger), and false-positive load. Do BTL sampling honestly — draw a random sample just below the current line and measure how many would have been productive.
3. Tabulate the alert-rate-vs-detection curve: as the threshold loosens, show incremental alerts and incremental productive alerts; as it tightens, show alerts suppressed and any productive/SAR-relevant activity lost (missed-risk exposure). Flag any threshold where BTL sampling surfaces productive alerts that the current setting drops.
4. Recommend a threshold with explicit rationale (target alert volume vs. acceptable missed-risk), and report the operating-cost implication. Hand off to the BSA officer stating assumptions: the lookback period, that historical dispositions proxy true risk, and that any threshold change requires model-validation sign-off before production.

# Notes

Wrong if BTL is skipped or under-sampled — tuning only ATL makes any threshold look efficient while hiding suppressed risk, which is exactly what examiners challenge. Disposition labels are the ground truth; if they are stale, inconsistent, or absent the productivity numbers are meaningless and must be marked UNVERIFIED. This skill produces a recommendation only — changing a live TM threshold is an irreversible, regulator-sensitive control change that requires independent model validation and governance approval. Do not use to tune a brand-new scenario with no production history (no dispositions to learn from).
