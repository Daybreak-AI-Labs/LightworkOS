---
title: Plan a trip to {{ destination }} for {{ duration }}
budget_dollars: 3.0
budget_wall_seconds: 1800
params:
  - destination
  - duration
---
Plan a personalized trip to {{ destination }} lasting {{ duration }}.

Before planning, batch any open questions to the user (dates, total
budget, solo/couple/family, mobility, food preferences). If facts in
the world model already answer these, skip the question.

Spawn three parallel researchers:
  - accommodations (hostels + mid-range + splurge options)
  - day-by-day activities (mix of paid + free)
  - restaurants (covering breakfast, lunch, dinner per day)

A writer synthesizes into a day-by-day itinerary. Write to
`trip-{{ destination }}.md`.

Success criteria:
  - file exists
  - one section per day matching the duration
  - each day has accommodation, activities, and meals
  - includes a packing list at the end
