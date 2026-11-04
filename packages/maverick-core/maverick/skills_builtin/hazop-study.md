---
name: hazop-study
triggers:
  - run a HAZOP on this process
  - do a process hazard study with guidewords
  - find deviations and safeguards for these nodes
tools_needed:
  - knowledge_search
---
# What this skill does

Conducts a Hazard and Operability (HAZOP) study: a systematic, guideword-driven examination of a process to surface hazardous or operability-impairing deviations from design intent. Working node by node, it applies standard guidewords (No, More, Less, Reverse, As Well As, Part Of, Other Than) to each parameter, then records the deviation, its causes, consequences, existing safeguards, and recommended actions in a HAZOP worksheet.

# Steps

1. Break the process into nodes (line segments, vessels, unit operations) and establish the design intent and operating parameters (flow, pressure, temperature, level, composition) for each. Pull the P&ID / process description and any prior incidents via `knowledge_search`; cite sources and mark unverified intent as `[assumed]`.
2. For each node x parameter, apply each guideword to generate a meaningful deviation (e.g. More + Pressure = overpressure). Discard combinations that are physically meaningless rather than padding the worksheet.
3. For each credible deviation, document plausible cause(s), realistic consequence(s) including safety/environmental/operability impact, and the existing safeguards (instrumentation, relief, procedures) actually present per the sources — not assumed protections.
4. Where safeguards are insufficient, draft a recommended action with a suggested owner; leave owner/priority blank where the team must decide. Report the worksheet by node, state assumptions and coverage gaps, and hand off — risk acceptance and action approval are human decisions.

# Notes

A HAZOP is invalid if guidewords are applied inconsistently across nodes, if credited safeguards are assumed rather than confirmed on the P&ID, or if "no deviation found" hides an unexamined node/parameter (record coverage, not just hits). It is qualitative hazard identification, not quantification — pair with LOPA/QRA when risk ranking is needed. This skill drafts findings and recommendations only; it does not approve design changes, set relief sizing, or accept residual risk — those are staged for a qualified human team. Do not use on a process whose design intent or current P&ID is unknown, and do not treat an out-of-date drawing as authoritative.
