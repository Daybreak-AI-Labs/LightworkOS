---
name: product-analytics-readout
triggers:
  - read out our product analytics
  - usage analytics summary
  - how is feature adoption trending
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Turns raw product-usage data into a decision-ready analytics readout: adoption, retention, and engagement for a product or feature over a defined window, with a short list of recommended actions. Output is a concise readout that connects each metric to a "so what" rather than a wall of numbers.

# Steps

1. Fix the question and window from real inputs: which product/feature, date range, and segment. Confirm the event schema and the active-user definition before querying — guessing either invalidates every number downstream.
2. Pull metrics with sql_query (or a provided spreadsheet): adoption (eligible users who used the feature), retention (cohorted return rate, e.g. D1/D7/D30 or weekly), and engagement depth (sessions/actions per active user). State the exact filters and denominators used; flag any data-quality gaps or instrumentation holes.
3. Compare against a baseline — prior period, target, or a holdout segment — and call out movements that exceed normal variance. Distinguish correlation from cause; do not attribute a lift to a release without an experiment or a clean event link.
4. Write the readout: headline metrics with trend, the two or three findings that matter, and recommended actions tied to each. Report assumptions (window, definitions, exclusions) and mark any metric built on incomplete tracking as "directional."

# Notes

The readout is wrong when adoption uses the wrong denominator, retention is non-cohorted (survivorship bias), or a metric silently drops users with broken instrumentation. Always show denominators and the active-user definition. Recommendations are advisory; launch/kill calls and any irreversible action stay with a human. Do not use when events are unverified or tracking shipped mid-window without backfill — fix instrumentation first and say the data is unreliable.
