---
name: engagement-survey-readout
triggers:
  - engagement survey
  - survey readout
  - engagement drivers
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Interprets an employee engagement survey to produce a readout: overall and segmented scores, the drivers most correlated with engagement, notable strengths and concerns, and a prioritized set of actions. Output is a scored summary by segment, a driver-importance analysis, and a ranked action list tied to the weakest high-impact drivers.

# Steps

1. Pull the response data via `sql_query`: item-level scores, the overall engagement/eNPS measure, and segment fields (team, tenure, location, level). Record response counts per segment and the response rate — segments below a minimum-n threshold must be suppressed to protect anonymity.
2. In a `spreadsheet`, compute overall and per-segment mean/favorable scores and the change vs. prior wave if a comparison is available. Mark any cell where n is too small to report rather than showing a number.
3. Run the driver analysis: correlate (or regress) each survey dimension against the overall engagement outcome to estimate importance, then plot importance vs. current score to find high-impact/low-score drivers (the priority quadrant). State that correlation is not causation and that drivers are associations, not proven levers.
4. Write the readout — top strengths, top concerns, the priority drivers — and a ranked action list addressing the high-impact weak drivers. Report it and state assumptions: response rate, suppression threshold, comparison basis, and any segments excluded.

# Notes

The readout is wrong if small-segment scores are shown (breaks anonymity and invites re-identification) or if driver correlations are presented as proven cause-and-effect — both are common failures. Open-text comments must be summarized in aggregate, never quoted in a way that identifies an individual. This produces a recommended action set for HR and people-managers to own; do not auto-assign actions or communicate results to teams without human review of the anonymity and framing. Not for compliance/whistleblower surveys or for evaluating individual managers punitively from thin data.
