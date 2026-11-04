---
name: oee-analysis
triggers:
  - run an OEE analysis on the line
  - why is equipment effectiveness down
  - break down our line losses
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Diagnoses Overall Equipment Effectiveness (OEE) for a production line or asset by decomposing it into Availability x Performance x Quality and attributing the shortfall to a ranked loss tree (the six big losses). Produces an OEE breakdown with each factor quantified against a stated theoretical maximum and the dominant losses prioritized for action.

# Steps

1. Pull the real production records for the asset and period from the source system via `sql_query`: planned production time, downtime events with durations and reason codes, ideal cycle time, total units run, and reject/rework counts. Confirm the time window and shift definition before computing anything; do not assume a 24h calendar.
2. Compute the three factors in a `spreadsheet`: Availability = run time / planned production time; Performance = (ideal cycle time x total count) / run time; Quality = good count / total count. OEE = product of the three. Flag any factor >1.0 as a data error (usually a wrong ideal cycle time), not a real result.
3. Build the loss tree: convert each downtime reason code, speed loss, and quality loss into lost-time and lost-unit terms, then rank by magnitude so the top 2-3 losses are explicit. Map each to the six-big-losses categories (breakdowns, setup/adjustment, idling/minor stops, reduced speed, startup rejects, production rejects).
4. Report the OEE breakdown, the ranked loss tree, and the single largest improvement opportunity. State the data window, the ideal-cycle-time source, and any reason codes that were missing or defaulted. Recommend — do not commit — corrective actions; line changes are a human decision.

# Notes

The output is wrong if the ideal cycle time is guessed rather than sourced (it silently inflates or deflates Performance) or if downtime reason codes are incomplete (unattributed losses hide the real driver — show them as an explicit "unclassified" bucket, never zero). Distinguish planned downtime (excluded from Availability) from unplanned; conflating them understates OEE. Do not benchmark against a generic "85% world class" target without the customer's own theoretical max. Not for utilization or capacity-planning questions — OEE measures effectiveness of running time, not whether to add a shift.
