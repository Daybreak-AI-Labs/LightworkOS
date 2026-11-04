---
name: control-chart-spc
triggers:
  - is this process metric in control
  - build a control chart for this data
  - check process capability Cp Cpk
tools_needed:
  - pandas_query
  - spreadsheet
---
# What this skill does

Applies Statistical Process Control to a time-ordered process metric to separate genuine signal (special-cause variation) from routine noise (common-cause variation). Produces the appropriate control chart with center line and control limits, flags out-of-control points against standard run rules, and — when specification limits exist — computes process capability indices (Cp, Cpk) to judge whether the process can meet spec.

# Steps

1. Load the metric from its real source (csv, table, or query) into `pandas_query`, preserving time/sample order. Confirm the data type and subgrouping: individual measurements (I-MR), subgroup averages (Xbar-R / Xbar-S), or counts/proportions (p, np, c, u) — pick the chart that matches; do not assume normality without checking.
2. Compute the center line and 3-sigma control limits from the data itself (control limits come from process variation, NOT from spec limits — never substitute one for the other). Use a stable baseline period if the user identifies one.
3. Apply run rules (point beyond 3 sigma, plus Western Electric / Nelson rules for runs, trends, and zone violations) and tag every violating point with the rule it broke and its timestamp. Render the chart in `spreadsheet`.
4. If spec limits (USL/LSL) are provided, compute Cp and Cpk and interpret them (Cpk < 1.33 typically inadequate) — but only after confirming the process is in control, since capability is meaningless on an unstable process. Report the chart, the flagged points, capability indices, and any assumptions; recommend investigation of signals but leave the disposition to a human.

# Notes

The output misleads if control limits are confused with spec limits, if capability is reported on an out-of-control process, if the wrong chart type is used for the data (e.g. an I-chart on count data), or if autocorrelated/non-normal data is treated as i.i.d. without noting it. A flagged point is a prompt to investigate, not proof of a defect — this skill recommends; halting a line, scrapping product, or re-centering a process is a human call. Do not use with too few points to estimate limits (commonly <20-25 subgroups) or for one-off measurements with no time order.
