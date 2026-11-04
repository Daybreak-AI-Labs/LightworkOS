---
name: funnel-conversion-analysis
triggers:
  - analyze our conversion funnel
  - where are users dropping off
  - find the biggest funnel leak
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Diagnoses where users leave a defined multi-step funnel (e.g., visit -> signup -> activate -> pay) and prioritizes the leaks by recoverable volume, not just by percentage. Produces a step-by-step conversion table, the largest drop-offs, and a ranked list of where intervention would move the most users — so the team fixes the leak that matters, not the scariest-looking rate.

# Steps

1. Pin down the funnel definition with the requester: the ordered steps, the event/table that marks each step, the entity (user/session), and the conversion window. Pull step-level counts via `sql_query`, ensuring each step counts distinct entities that also completed prior steps (a true sequential funnel, not independent event totals).
2. Compute step-to-step conversion rate and absolute drop-off (users lost) at each transition, plus overall end-to-end conversion. Verify totals reconcile (each step <= the prior); if a step exceeds its predecessor, the join or ordering is wrong — stop and fix before interpreting.
3. Rank leaks by recoverable volume = users lost × downstream value (or simply users lost when value is unknown), so a small-percentage drop on a huge step can outrank a large-percentage drop on a tiny one. Segment the worst step by an available dimension (channel, device, plan) to see if the leak is concentrated.
4. Report the funnel table, the top 2-3 prioritized leaks with where they concentrate, and one testable hypothesis per leak — clearly separating what the data shows from what is conjecture. State the window, entity definition, and any segments with thin samples.

# Notes

The analysis is wrong when steps are counted as independent event totals instead of sequentially gated, when the conversion window is too short (legitimate conversions look like drop-offs) or too long (stale), or when bots/internal traffic inflate the top of funnel — filter and say so. Prioritizing by percentage alone is the classic mistake; lead with recoverable volume. Hypotheses are recommendations for experiments, not proven causes — any rollout (UX change, gating change) is a human decision. Do not use for non-sequential or branching journeys where a strict step order doesn't hold.
