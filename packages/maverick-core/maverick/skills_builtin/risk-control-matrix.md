---
name: risk-control-matrix
triggers:
  - build an RCM
  - risk control matrix for this process
  - map process risks to controls
tools_needed:
  - spreadsheet
  - knowledge_search
---
# What this skill does

Builds a Risk-and-Control Matrix (RCM) for a single named business process: decompose the process into steps, enumerate the risks at each step, map existing controls, and define a test for each control. Produces a structured spreadsheet with risk, risk rating, control, control type (preventive/detective), owner, and test of design/operating effectiveness. Use it to baseline control coverage before an audit or to spot uncovered risks.

# Steps

1. Pin the scope: get the exact process name, its boundaries (start/end events), and the source of the process narrative (SOP, flowchart, walkthrough notes). Use knowledge_search to pull the documented procedure and any prior RCM for this process; if none exists, mark the narrative as "unverified — derived from interview" and do not invent steps.
2. Decompose the process into discrete steps in execution order. For each step, enumerate what could go wrong (financial, operational, compliance, fraud, IT). Rate each risk by likelihood x impact (e.g. 1-5 each) and flag the residual driver. Cite the framework you score against (COSO, the client's own taxonomy) rather than improvising scales.
3. Map each risk to the control(s) that mitigate it. Record control type (preventive/detective, manual/automated), frequency, the named owner (role, not just a person), and whether it is key. Flag any risk with no control as a coverage gap.
4. Define a test of design and a test of operating effectiveness per key control (sample size, evidence to inspect). Write the matrix to a spreadsheet with one row per risk-control pair. Hand off the gap list separately, state which rows are unverified, and note that remediation of gaps is a recommendation for the control owner to accept — do not close gaps yourself.

# Notes

The output is wrong if risks are listed without tracing to a real process step, if controls are asserted without an owner or test, or if the likelihood/impact scale is invented rather than the client's. Coverage gaps (risk with no control) are the highest-value finding — never silently drop them to make the matrix look complete. Mark any step or control you could not corroborate against a document as unverified. This skill produces a draft baseline; the control owner and audit lead decide ratings and whether gaps are accepted, remediated, or risk-accepted. Do not use it as a substitute for a formal walkthrough when one is contractually required.
