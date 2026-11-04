---
name: nps-csat-driver-analysis
triggers:
  - nps drivers
  - csat analysis
  - satisfaction drivers
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Analyzes NPS or CSAT survey data to find what actually drives the scores: quantifies movement by segment, mines open-text verbatims into themes, and ranks drivers by impact and prevalence. Produces a driver-analysis report with verbatim themes and a prioritized action list. It surfaces and prioritizes; it does not launch the fixes.

# Steps

1. Pull the survey data with `sql_query`: scores over the period, respondent segment (plan/tenure/region/product), and free-text comments. Record the date range, sample size per segment, and response rate; flag segments too small to be reliable.
2. Compute the score view in `spreadsheet`: overall NPS/CSAT, trend, and breakdown by segment to locate where satisfaction is highest/lowest and where it moved. Note statistical caution on thin cells rather than over-reading them.
3. Code the verbatims into themes (e.g., onboarding, performance, pricing, support responsiveness, missing feature). For each theme record frequency, average score of respondents who mention it, and 2-3 representative quotes verbatim — quotes are reproduced, never paraphrased into claims.
4. Rank drivers by impact (score gap when present vs. absent) x prevalence, and translate the top few into recommended actions with the owning function. Report the analysis stating assumptions, sample limits, and which themes are low-confidence; hand off — recommendations are for a human to prioritize and act on.

# Notes

Wrong if it reports drivers from tiny samples as if robust, paraphrases a verbatim into a stronger claim than the customer made, or implies correlation is causation — state it as association. Always show sample sizes and the period; a driver from 4 responses is a hypothesis, not a finding. Don't use when there's no open-text (no verbatims to theme) or for a single account's feedback (use account review instead). The skill recommends; it does not ship product or process changes.
