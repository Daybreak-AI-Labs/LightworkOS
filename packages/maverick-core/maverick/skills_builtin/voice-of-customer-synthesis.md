---
name: voice-of-customer-synthesis
triggers:
  - voice of customer
  - voc synthesis
  - feedback themes
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Synthesizes multi-source voice-of-customer signal (survey verbatims, support tickets, NPS comments, reviews, interview notes) into a ranked set of themes with severity, prevalence, and recommended actions. Output is a VoC synthesis: theme list with frequency and impact, representative quotes, and a prioritized action set, each traceable to source.

# Steps

1. Pull the raw signal: `sql_query` structured feedback (ticket tags, NPS verbatims, CSAT comments, churn reasons) over a defined window; `knowledge_search` unstructured sources (interview notes, review exports). Record the window, source counts, and any sampling bias (e.g. only detractors are quoted).
2. Cluster into themes by meaning, not keyword: group comments into a small set of named themes, each with a one-line definition. Keep verbatim quotes attached so a theme can be audited back to real customer language; do not merge distinct pains into a vague mega-theme.
3. Score each theme: prevalence (count/share of sources, with N), severity (revenue/churn/blocker impact — cross-reference account value via `sql_query` where possible), and trend vs prior period. Mark any severity that is inferred rather than measured as an estimate.
4. Recommend prioritized actions per top theme (owner-suggested, not assigned) and hand off the synthesis, stating the source window, sample biases, and which impact figures are estimated vs measured.

# Notes

The synthesis is wrong if it over-weights the loudest channel, treats raw comment counts as prevalence without normalizing for volume, or presents inferred business impact as fact. Sampling bias is the main failure mode — a VoC built only from support tickets reflects problems, not the whole base; state the bias explicitly. This skill recommends; theme-driven roadmap or staffing decisions are the human's call. Do not use as a substitute for a quantified NPS/CSAT score — VoC explains the "why," it does not replace the metric, and never fabricate quotes to fill a thin theme.
