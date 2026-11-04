---
name: oee-loss-analysis
triggers:
  - analyze our OEE
  - why is equipment effectiveness low
  - break down the six big losses
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Diagnoses Overall Equipment Effectiveness (OEE) for a line, cell, or asset by decomposing it into Availability, Performance, and Quality, then attributing the gap to the six big losses (breakdowns, setup/adjustment, idling/minor stops, reduced speed, defects, startup/yield). Produces an OEE breakdown with a quantified loss tree and ranked corrective actions.

# Steps

1. Pull the production record from the source system: per-asset planned production time, run time, downtime events with reason codes, ideal cycle time, total count, and good count. Use `sql_query` against the MES/historian tables; if a field is missing or estimated, mark it unverified rather than substituting a guess.
2. Compute the three factors with explicit formulas — Availability = Run Time / Planned Production Time; Performance = (Ideal Cycle Time x Total Count) / Run Time; Quality = Good Count / Total Count; OEE = A x P x Q. Cross-check that Performance does not exceed 1.0 (a sign the ideal cycle time is wrong).
3. Map each loss into the six-big-losses tree in `spreadsheet`: roll downtime reason codes into breakdowns vs setup/adjustment, speed loss into idling/minor-stops vs reduced-speed, and scrap/rework into defects vs startup-yield. Rank by lost minutes or lost units so the largest contributor is unambiguous.
4. Recommend corrective actions targeting the top two losses (e.g., SMED for setup, autonomous maintenance for breakdowns), each tied to its loss bucket and expected OEE point recovery. Report the breakdown, state every assumption (shift calendar, planned-stop policy, ideal cycle source), and flag any unverified inputs.

# Notes

Output is wrong if planned production time silently includes planned stops (deflates Availability) or if ideal cycle time is set to nameplate rather than demonstrated best — both distort which loss dominates. World-class OEE benchmarks (~85%) are context-dependent; do not assert a target without the customer's own demand/takt. Reason-code coverage below ~80% of downtime makes the loss tree unreliable — say so. This skill diagnoses and recommends; it does not change machine setpoints, maintenance schedules, or staffing — those are staged for a human owner to approve.
