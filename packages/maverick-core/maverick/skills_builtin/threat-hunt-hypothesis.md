---
name: threat-hunt-hypothesis
triggers:
  - plan a threat hunt
  - hunt hypothesis for this technique
  - proactive detection sweep
tools_needed:
  - knowledge_search
---
# What this skill does

Converts a concern (a TTP, a threat-intel report, an anomaly) into a structured, hypothesis-driven threat hunt plan. Produces a testable hypothesis, the data sources and queries to test it, the abnormal-vs-normal decision criteria, and explicit success/exit conditions — a runbook a hunter can execute, not the hunt's findings.

# Steps

1. Frame the hypothesis as a falsifiable statement grounded in real intel: "If [actor] is doing [technique] in our environment, we would see [observable] in [data source]." Use `knowledge_search` to pull the relevant ATT&CK technique, threat report, or prior hunt; cite each and map the behavior to specific observables. Mark any assumption that is not backed by a source.
2. Confirm the data exists to test it: name the required logs/telemetry, the retention window, and whether coverage is complete. If the data needed to confirm or refute the hypothesis is not collected, the hunt cannot conclude — record that as a visibility gap and a detection-engineering follow-up rather than proceeding blind.
3. Write the hunt queries and the analysis approach: the baseline of "normal," the pivots, and the threshold or anomaly that distinguishes malicious from benign. Keep queries scoped to the retention window and sized so they return a reviewable volume; note expected benign noise so the hunter isn't misled by it.
4. Define success criteria and outcomes — what confirms the hypothesis, what refutes it, what is inconclusive — and the hand-off: confirmed activity escalates to incident response, a refuted-but-valuable pattern becomes a detection rule, a visibility gap becomes a logging request. State assumptions and present the plan for a human to run; do not act on raw hits as if confirmed.

# Notes

The plan is wrong if the hypothesis is unfalsifiable, if it assumes telemetry that isn't collected, or if "anomaly" is undefined so every result looks suspicious. Never present unreviewed query hits as confirmed compromise — escalation to IR is the human-decided, consequential step. Do not fabricate actor TTPs; ground them in cited intel or mark them speculative. Not for responding to a confirmed incident (use IR) or for standing up continuous monitoring (that is detection-rule-design).
