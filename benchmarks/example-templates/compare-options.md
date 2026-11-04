---
title: Compare {{ category }} — {{ option_a }} vs {{ option_b }}
budget_dollars: 2.0
budget_wall_seconds: 1200
params:
  - category
  - option_a
  - option_b
---
Produce a comparative analysis of two {{ category }} options: {{ option_a }} and {{ option_b }}.

Decompose into parallel researchers:
  - one researcher fetches docs + reviews for {{ option_a }}
  - one researcher fetches docs + reviews for {{ option_b }}
  - an analyst synthesizes both into a comparison table

Deliverable: a `comparison.md` file in the workspace with:
  1. A summary table covering price, learning curve, ecosystem,
     performance, and notable gotchas.
  2. A short "when to pick which" section.
  3. Citations for every claim (URLs).

Success criteria:
  - file exists
  - table has all five columns
  - each row has a non-empty cell
  - at least 6 URLs cited
