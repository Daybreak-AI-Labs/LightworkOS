---
name: sox-test-of-controls
triggers:
  - control testing
  - test of controls
  - sox testing
tools_needed:
  - knowledge_search
---
# What this skill does

Plans and documents a SOX test of controls for a named control, producing a test plan that states the control objective, the test attributes to inspect, a defensible sample, and a results template ready for the tester to populate. Handles the goal class "design a repeatable test that proves whether a key control operated effectively over the period."

# Steps

1. Pull the control's definition from the control matrix or RCM via knowledge_search: control ID, owner, frequency, control type (preventive/detective, manual/automated), and the assertion/risk it addresses. Quote the source; if the control description is missing or stale, flag it and stop rather than infer attributes.
2. Derive the testable attributes from the control wording — one attribute per "what must be true" (e.g. approval present, approver independent, performed timely, evidence retained). Map each attribute to the test method (inquiry, observation, inspection, re-performance); inspection/re-performance carry the evidence weight.
3. Set the sample by control frequency using a standard sizing convention (e.g. daily ~25, weekly ~5, monthly ~2-3, quarterly 2, annual 1; automated controls = 1 + a configuration/change-management check). State the population source, period covered, and selection method (random/haphazard); cite the sizing convention you applied.
4. Emit the test plan and a per-sample results template (columns: sample ID, date, attribute pass/fail, evidence reference, exception note). Report assumptions (population completeness, sizing basis) and hand off for tester execution. Do not conclude effective/ineffective — that is the tester's call after execution.

# Notes

Output is wrong if attributes are invented rather than traced to the control wording, if the sample size doesn't match the actual control frequency, or if population completeness is assumed without evidence. Automated controls need a baseline + change-management test, not a transaction sample. This skill drafts the plan and template only; the conclusion on operating effectiveness, and any deficiency severity rating, is a human auditor decision. Do not use for control design assessment (a different procedure) or for substantive financial testing.
