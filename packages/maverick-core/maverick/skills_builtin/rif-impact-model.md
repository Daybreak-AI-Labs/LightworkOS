---
name: rif-impact-model
triggers:
  - rif
  - layoff model
  - reduction in force
tools_needed:
  - spreadsheet
---
# What this skill does

Models a reduction in force (RIF) scenario: computes severance and run-rate cost, a one-time vs. ongoing savings view, a timeline, and a preliminary disparate-impact check across protected classes. Produces a spreadsheet a leader and HR/legal can review before any decision is made.

# Steps

1. Gather inputs: the candidate impacted-population roster (role, comp, tenure, location, and demographic fields where lawfully available), severance policy, and benefits-continuation terms. Build the spreadsheet from the actual roster; never synthesize employees or demographics.
2. Compute cost: per-person severance (formula from policy), PTO payout, benefits bridge, and one-time total; then ongoing run-rate savings (annualized comp + loaded benefits) and payback period.
3. Run a disparate-impact check: compare selection rates by age band, gender, race/ethnicity, and other protected classes against the retained population; flag any group whose selection rate trips the four-fifths (80%) rule as a finding requiring legal review — do not conclude legality.
4. Build the timeline (notice, WARN-Act thresholds if applicable, separation dates) and report the model with every assumption listed. Hand off to HR and legal; state explicitly that adverse-impact findings are flags, not clearance.

# Notes

Output is wrong if severance formulas don't match policy, if WARN/local-notice thresholds are ignored, or if the impact check is presented as a legal conclusion. A RIF is irreversible and legally sensitive: this skill only stages a model — the decision to proceed, and any final selection, requires named HR, legal, and executive sign-off. Do not use it to pick individuals; it evaluates a roster others have proposed. Mark demographic fields that are unavailable rather than imputing them.
