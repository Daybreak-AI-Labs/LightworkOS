---
name: process-mining-readout
triggers:
  - process mining
  - process discovery
  - find automation candidates
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Reads the output of a process-mining run (event log, variant table, or discovered process graph) to surface bottlenecks, rework loops, and the activities worth automating. Produces a readout ranking automation candidates by an ROI estimate (frequency x manual handling time x rate), with the assumptions behind each number stated explicitly.

# Steps

1. Load the real process-mining export — event log or variant/activity table — via sql_query or spreadsheet. Confirm the schema: case id, activity, start/end timestamps, resource. Do not proceed if timestamps or case ids are missing; the analysis depends on them.
2. Compute per-activity and per-transition metrics from the actual data: frequency, median and p90 cycle time, wait time, rework/loop count, and rejoin points. Flag the longest waits and most-repeated loops as bottlenecks.
3. Rank automation candidates: high-frequency, high-manual-effort, low-variance, rule-driven activities score highest; high-variance or judgment-heavy ones score low. Estimate ROI = volume x handling time saved x loaded labor rate; mark every input you assumed (e.g. handling time if not in the log) as ASSUMED.
4. Report the readout: top bottlenecks, ranked candidates with ROI and confidence, and recommended next artifact (PDD for the top candidate). State data window, case count, and all assumptions. Recommend only — do not commit any automation.

# Notes

Output is wrong if handling-time or labor-rate inputs are invented silently — always tag assumed values and give a range, not a point estimate. Mining captures the as-is path, not the should-be: a frequent activity may be frequent because the process is broken, so flag rework before recommending you automate it. Skip this skill when the event log is partial (missing end timestamps, sampled cases) — cycle-time and ROI figures will be unreliable. ROI ranking is a recommendation; a human owns the decision to fund a build.
