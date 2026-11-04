---
name: csat-driver-analysis
triggers:
  - what drives our csat
  - dsat analysis
  - satisfaction analysis
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Finds the operational and experiential drivers of CSAT/DSAT by correlating survey scores with ticket attributes and mining verbatim comments for recurring themes. Produces a driver analysis: which factors (handle time, reopens, channel, agent, product area) move satisfaction, the dominant DSAT verbatim themes, and a prioritized list of where to intervene.

# Steps

1. Pull scored surveys joined to their tickets for the trailing window via sql_query: CSAT/DSAT score, channel, contact reason, handle/resolution time, touches, reopen flag, escalation flag, agent/team, and the free-text verbatim. Keep only surveys actually linked to a resolvable ticket; report the response rate and any sampling bias (e.g. only escalations surveyed).
2. Quantify drivers: compare DSAT rate across each dimension (channel, reason, time-to-resolve buckets, reopened vs not). Use the spreadsheet to build the cut tables and rank dimensions by DSAT-rate lift over baseline. Note correlation is not causation — flag confounded cuts (e.g. a slow channel that also handles hard problems).
3. Theme the verbatims: cluster DSAT comments into recurring themes (slow, repeated contact, wrong answer, tone, policy) with a representative quote and count per theme. Quote verbatims as-is; never paraphrase into a stronger claim than the customer made.
4. Report top quantitative drivers and top verbatim themes side by side, with a prioritized intervention list (driver -> proposed fix -> tickets affected). State assumptions (window, response rate, linkage) and hand off; recommend only.

# Notes

Output is wrong if low response rate or survey-only-on-escalation bias is ignored, if a driver is reported as causal without checking confounds, or if verbatim themes are inflated beyond what customers said. Small per-agent or per-segment samples produce noisy DSAT rates — suppress cells below a minimum n. Do not name-and-rank individual agents as a performance verdict; this is diagnostic, not disciplinary. Not for unscored or unlinked surveys.
