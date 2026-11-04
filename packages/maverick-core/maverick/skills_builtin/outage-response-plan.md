---
name: outage-response-plan
triggers:
  - outage response
  - storm response
  - restoration
tools_needed:
  - knowledge_search
---
# What this skill does

Produces an outage/storm restoration plan for a utility event: sequences restoration by priority, assigns and stages crews against the damage forecast, and drafts the customer and stakeholder communications cadence. Output is an actionable runbook aligned to the utility's emergency response procedures.

# Steps

1. Establish the event scope from the inputs given (affected circuits, estimated customers out, damage assessment, weather forecast) and retrieve the utility's emergency response plan, mutual-assistance procedures, and critical-facility list via knowledge_search; cite the procedure documents and flag anything not found.
2. Set the restoration priority order per those procedures — typically public-safety hazards and critical loads (hospitals, water/wastewater, 911, shelters) first, then circuits restoring the most customers per crew-hour — and map each priority to the affected circuits.
3. Assign and stage crews (internal + mutual aid) against the damage forecast: estimate crew-hours per priority, identify staging sites and material needs, and produce an ETR (estimated time of restoration) per zone with stated confidence.
4. Draft the communications cadence — initial notification, periodic ETR updates, critical-customer and regulator/EOC notifications, and all-clear — and hand off the plan stating which inputs are forecasts vs. confirmed and which steps require dispatcher/EOC authorization before execution.

# Notes

Wrong if priorities deviate from the utility's approved emergency procedures, critical facilities are missed, or ETRs are stated without confidence and then treated as commitments — public-safety sequencing is not negotiable and overstated ETRs erode trust. This plan drafts and recommends; actual crew dispatch, energization, switching, and public ETR commitments are decisions for the storm room, dispatchers, and incident commander. Do not use for routine single-customer trouble tickets or for switching orders, which follow separate operational authority.
