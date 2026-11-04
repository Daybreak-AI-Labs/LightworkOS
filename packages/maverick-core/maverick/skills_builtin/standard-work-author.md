---
name: standard-work-author
triggers:
  - write standard work for this process
  - draft a work instruction
  - create an SOP for the operation
---
# What this skill does

Authors standard work for a repeatable manual or semi-automated process: the agreed sequence of steps performed to takt, with embedded quality checks and the standard WIP. Produces a standard work document with sequenced steps, time elements, takt alignment, key points/reasons, and in-process quality verifications.

# Steps

1. Gather the current method and constraints: the work elements in sequence, observed time per element, required tools/materials, safety notes, and known defect modes. Pull existing instructions, specs, and quality requirements via `knowledge_search`; capture the demonstrated best-known method, not an idealized one, and tag any element whose time is estimated.
2. Compute takt time (available time / customer demand) and total manual cycle time, then check the work content against takt — flag if cycle time exceeds takt (line won't keep up) or falls well under (imbalance/overproduction risk).
3. Write each step as a single imperative action with its key point (what to do precisely) and reason (why it matters for quality/safety), and place in-process quality checks at the points where defects are caught cheapest. Specify standard WIP and the start/stop boundary of the work.
4. Assemble the document — header (process, takt, revision), the step table, quality checks, and a sign-off line for the area lead. Hand off as a draft; state assumptions (demand basis for takt, time-study sample size, source of the quality spec) and mark unverified elements.

# Notes

The document is wrong if it codifies a method the operators don't actually follow, omits the reason behind key points (so deviations creep back in), or sets takt from a stale demand figure. Do not invent torque values, tolerances, or cycle times — cite the spec or mark them TBD for an engineer. Not appropriate for non-repeating or highly variable work where standardization would be premature. Standard work is a draft proposal: it must be validated at the gemba and approved by the process owner before it becomes the controlled standard.
