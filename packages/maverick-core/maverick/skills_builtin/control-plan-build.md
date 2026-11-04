---
name: control-plan-build
triggers:
  - build a process control plan
  - set up process controls for this line
  - define reaction plan for out-of-control
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

Builds a process control plan that links each process step's key characteristics to a specification, a measurement method, a sampling plan, the control method, and a reaction plan for out-of-spec conditions. Produces a control plan table that operators and quality can run from, traceable to the source specs and any upstream FMEA.

# Steps

1. Gather the process steps and their key product/process characteristics; use knowledge_search to pull governing specs, tolerances, FMEA high-RPN items, and existing SOPs. Cite each spec source; flag any characteristic lacking a documented tolerance as `spec missing — needs owner`.
2. For each characteristic define: specification/tolerance, measurement technique and gauge, sample size and frequency, and the control method (SPC chart, check sheet, poka-yoke, 100% inspection).
3. Write a concrete reaction plan per characteristic: who is notified, containment of suspect product, and the stop/adjust criteria when a reading is out of control.
4. Assemble the control plan in the spreadsheet (one row per characteristic), and hand off, listing any missing specs or undefined gauges as open items for a human to resolve before release.

# Notes

The plan is wrong if a reaction plan is generic ("investigate") instead of specifying containment and a decision-maker, or if a characteristic is controlled with no real measurement method. Never invent tolerances — an unknown spec is an open item, not a filled cell. This skill drafts the control plan; it does not authorize production release or override existing quality holds — a quality owner approves it. Do not use it for a process whose characteristics and specs are not yet defined.
