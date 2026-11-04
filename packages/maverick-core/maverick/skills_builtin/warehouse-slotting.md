---
name: warehouse-slotting
triggers:
  - slotting
  - warehouse layout
  - pick optimization
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Generates a warehouse slotting plan that places SKUs into pick locations by velocity and physical fit to minimize pick travel and congestion. Produces a recommended SKU-to-location assignment, a move list to transition from the current layout, and the expected reduction in pick travel. Output is a recommendation a warehouse supervisor reviews before re-slotting labor is scheduled.

# Steps

1. Pull order-line history via sql_query to compute per-SKU pick velocity (lines and units per period), affinity (SKUs frequently picked together), and any handling flags (hazmat, cold, oversize). Pull the current slot map: location, zone, pick-face dimensions, and capacity. Confirm the date range is representative and flag SKUs with no recent demand.
2. Rank SKUs by velocity and assign the fastest movers to the most ergonomic, lowest-travel golden zones (e.g., forward-pick, waist height, near pack-out), respecting cube fit, weight (heavy low), and handling constraints. Keep high-affinity SKUs near each other to shorten multi-line picks.
3. In the spreadsheet, validate that no location is over-capacity and that hazmat/cold/zone rules are not violated, then build the move list (SKU, from-location, to-location) and estimate travel-distance reduction vs. the current slotting using velocity-weighted pick distances.
4. Report the slotting plan, the prioritized move list, and the projected pick-travel and congestion improvement. State assumptions (demand period is representative of forward demand, dimensions accurate, no seasonality re-slot) and stage the move list for supervisor approval and labor scheduling.

# Notes

Output is wrong if the demand window is unrepresentative (a promo or seasonal spike mis-ranks velocity), if pick-face dimensions/weights are stale (assigns a SKU that physically won't fit), or if handling rules are dropped (placing hazmat or cold items in non-compliant slots is a safety/compliance failure, not just inefficiency). Re-slotting consumes labor and temporarily disrupts picking: present the move list as a staged recommendation, never auto-apply, and sequence moves to avoid location collisions. Do not use for cross-facility flow (use network-optimization) or routing between sites (use transportation-optimization).
