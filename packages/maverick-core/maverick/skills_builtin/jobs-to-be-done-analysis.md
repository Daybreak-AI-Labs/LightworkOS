---
name: jobs-to-be-done-analysis
triggers:
  - run a jtbd analysis
  - what jobs to be done does this product serve
  - map customer jobs and outcomes
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a Jobs-to-be-Done (JTBD) analysis for a given product or feature: the functional, emotional, and social jobs customers hire it for, the desired outcomes attached to each job, and the gaps where the product underserves a job. Output is a structured JTBD map that grounds prioritization and positioning in customer goals rather than features.

# Steps

1. Pull the scope from real inputs: which product/segment, and any existing research. Use knowledge_search over interview notes, support tickets, win/loss records, and survey verbatims; cite each source. If no primary research exists, say so and mark every job "hypothesis, unvalidated."
2. Extract candidate jobs as "When [situation], I want to [motivation], so I can [expected outcome]." Classify each as functional, emotional, or social. Quote the evidence line that supports each job; never invent a job to fill a category.
3. For each job, list its desired outcomes as measurable statements (direction + metric + object, e.g. "minimize time to first value"). Tag each outcome importance and current satisfaction only where data backs it; otherwise mark "needs validation."
4. Identify gaps: high-importance/low-satisfaction jobs and outcomes the product does not address. Report the JTBD map (jobs, outcomes, gaps), separating validated from hypothesized, and state assumptions plus the next research step to confirm them.

# Notes

The analysis is wrong when jobs are restated features ("uses dashboard") instead of customer goals, or when importance/satisfaction scores are asserted without survey data — keep those marked unverified. JTBD describes motivation, not solutions; do not let the map prescribe a roadmap. This is a draft input for prioritization; a human owns roadmap decisions. Do not use for pure UX-flow debugging or for markets where no customer signal exists at all — gather research first.
