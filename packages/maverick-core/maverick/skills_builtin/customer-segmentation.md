---
name: customer-segmentation
triggers:
  - customer segmentation
  - segment customers
  - behavioral segments
tools_needed:
  - sql_query
  - pandas_query
---

# What this skill does

Builds an actionable customer segmentation: segments defined on behavior and value that map to distinct go-to-market or product actions, not just demographics.

# Steps

1. Define the segmentation goal first (targeting, retention, pricing) — the goal dictates the features. Pull the population and candidate features with `sql_query`.
2. Engineer behavioral and value features (recency, frequency, monetary, adoption, lifecycle) and build segments in `pandas_query` via rules or clustering, validating they're stable and distinguishable.
3. Profile each segment: size, value, defining traits, and — critically — the action it implies. A segment you can't act on differently is noise.
4. Size the opportunity per segment and recommend the play. State assumptions (features, method, k) and hand off.

# Notes

Segmentations fail when they're demographic-only, unstable across periods, or imply no different action. Tie every segment to a move. Pricing or targeting changes are business decisions this skill informs, not makes.
