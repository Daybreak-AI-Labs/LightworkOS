---
name: pay-equity-analysis
triggers:
  - run a pay equity analysis
  - check for a pay gap
  - equal pay analysis
tools_needed:
  - pandas_query
  - spreadsheet
---
# What this skill does

Analyzes pay equity across protected or comparison groups (e.g. gender, race/ethnicity) by measuring both raw and controlled pay gaps. Produces an analysis that separates explainable variation (level, tenure, location, role) from residual gaps and flags groups/cohorts warranting remediation review.

# Steps

1. Load the compensation dataset and confirm the columns available for controls (job level, role family, location, tenure, performance, FTE) and the group variable(s) to test; restrict to comparable cohorts — never compare across non-equivalent jobs.
2. With pandas_query, compute raw mean/median gaps per group, then fit a controlled model (regression of pay on legitimate factors + group indicator) so the residual group coefficient is the controlled gap; report sample sizes and suppress cohorts below a privacy threshold (commonly n<5).
3. Identify statistically significant residual gaps (note p-values and confidence intervals), and in spreadsheet rank cohorts by gap size and headcount affected to size the remediation cost.
4. Hand off the analysis with controlled-gap estimates, flagged cohorts, the control set used, and stated limitations; mark it DRAFT for legal/comp review — remediation pay adjustments are a privileged, human-decided action.

# Notes

Output is wrong if controls smuggle in tainted variables (e.g. starting salary that itself encodes bias), if cohorts are too small to be reliable, or if raw and controlled gaps are conflated. Significance is not causation — a flagged gap is a prompt to investigate, not proof. Suppress small cells to protect privacy. Do not use to defend a predetermined conclusion; this is typically done under legal privilege, so route findings through counsel and never auto-apply adjustments.
