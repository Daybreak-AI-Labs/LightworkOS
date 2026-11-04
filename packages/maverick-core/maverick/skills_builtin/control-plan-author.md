---
name: control-plan-author
triggers:
  - control plan
  - process control
  - reaction plan
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

Authors a control plan for a manufacturing or service process: the documented set of characteristics to control, their specifications and tolerances, the measurement method and sampling, and the reaction plan when a characteristic goes out of control. Output is a structured control plan table (one row per characteristic) ready for review by the process owner. It documents controls; it does not run or change the process.

# Steps

1. Confirm the process scope and stage (prototype / pre-launch / production) and gather inputs — process steps, known critical-to-quality characteristics, and any prior FMEA — from supplied materials. Reference the governing format via `knowledge_search` (e.g. AIAG control plan, IATF 16949) and name it.
2. For each process step, list product and process characteristics. Carry special/critical characteristics from the FMEA where one exists; flag any characteristic added without a documented source as unverified.
3. For each characteristic record specification and tolerance, measurement technique/gauge, sample size and frequency, and control method (SPC chart, check, poka-yoke). Use only specs from the drawing/standard provided — do not invent tolerances.
4. Define a reaction plan per characteristic: the trigger (out-of-spec or out-of-control signal), containment of suspect product, and escalation/owner. Build the full plan in the `spreadsheet`, one row per characteristic.
5. Report the control plan table plus an assumptions/gaps list (missing specs, characteristics lacking a gauge or reaction plan), and state it is a draft for the process/quality owner to approve before it governs production.

# Notes

Output is wrong if specs or tolerances are fabricated rather than taken from the drawing/standard, if a characteristic has no measurement method or no reaction plan, or if special characteristics from the FMEA are dropped. Cite the source of every spec and the control-plan format used; mark anything unsourced as unverified. This is a draft deliverable — it does not authorize production or alter setpoints; the process owner approves before it takes effect. Not for ad-hoc inspection checklists or when no specifications/FMEA exist to ground the controls.
