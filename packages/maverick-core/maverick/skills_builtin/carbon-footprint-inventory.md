---
name: carbon-footprint-inventory
triggers:
  - carbon footprint
  - ghg inventory
  - scope 1 2 3 emissions
tools_needed:
  - spreadsheet
  - pandas_query
---

# What this skill does

Builds a greenhouse-gas inventory across Scopes 1-3 using the GHG Protocol: activity data, emission factors, and a documented methodology.

# Steps

1. Set the organizational and operational boundary and the consolidation approach (operational vs financial control) before any math.
2. Collect activity data by source and apply documented emission factors; compute Scope 1 (direct), Scope 2 (purchased energy, location and market based), and the relevant Scope 3 categories in `spreadsheet`/`pandas_query`.
3. Document every factor source, assumption, and any estimation/extrapolation; flag the categories with low data quality.
4. Produce the inventory with totals by scope and category and a methodology appendix. State assumptions and hand off for verification.

# Notes

GHG inventories go wrong on boundary errors, double counting Scope 2 market vs location, and undocumented factors. The methodology trail is the deliverable. Reported figures need third-party verification before disclosure.
