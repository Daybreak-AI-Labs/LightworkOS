---
name: sox-control-walkthrough
triggers:
  - do a SOX walkthrough
  - document and test an ICFR control
  - control testing for this process
  - test of design and operating effectiveness
tools_needed:
  - knowledge_search
---
# What this skill does

Documents and tests one ICFR (internal control over financial reporting) control for SOX. Produces a walkthrough package: a narrative/flowchart of the process and control point, the test of design (is the control capable of preventing/detecting the risk), and the test of operating effectiveness (did it actually operate) with a sampled evidence trail and a conclusion. Output is a draft workpaper for the control owner and auditor.

# Steps

1. Identify the control from the input: control ID, the financial-statement assertion and risk it addresses, owner, frequency, and whether it is preventive/detective and manual/automated. Pull the existing control description via `knowledge_search` (RCM / control matrix) — do not redefine the control from scratch.
2. Walk the process: trace one real transaction end to end through the control point, documenting each handoff, system, and the evidence the control produces (approval, reconciliation, system config). Note any step you could not corroborate as "unverified — owner to confirm."
3. Test of design: assess whether the control, as operating, would catch the risk — check for gaps (no segregation of duties, reliance on an untested IPE/report). Then test operating effectiveness on a sample sized to the control frequency, recording each item's evidence and pass/fail; cite every artifact examined.
4. Conclude (design effective? operating effective?), list exceptions and their potential deficiency severity, and report. State assumptions and sample basis; a deficiency rating is a RECOMMENDATION — the control owner and auditor make the final determination.

# Notes

Wrong if: the sample is too small for the control frequency, an exception is rationalized away instead of logged, or report/IPE completeness-and-accuracy is assumed without testing the underlying data. Never conclude "effective" from a single happy-path walkthrough — design and operating effectiveness are separate tests. Do not assert a deficiency severity (deficiency vs. significant vs. material weakness) as final — stage it for human aggregation across controls. Not for designing new controls — this tests an existing one.
