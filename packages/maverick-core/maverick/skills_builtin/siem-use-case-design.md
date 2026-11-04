---
name: siem-use-case-design
triggers:
  - design siem use cases
  - build detection content
  - new alert rules for the soc
tools_needed:
  - knowledge_search
---
# What this skill does

Designs SIEM detection use cases that turn a threat or requirement into deployable, tunable alert logic. Produces a use-case set where each entry specifies the detection intent, the required log sources, the detection logic, expected false positives, and a tuning/triage plan.

# Steps

1. Anchor on real inputs: the threats or compliance drivers to cover, the log sources actually onboarded (auth, EDR, firewall, DNS, cloud audit, identity), and the SIEM platform. Map intended use cases to MITRE ATT&CK techniques via `knowledge_search`; flag any technique whose required telemetry is NOT onboarded as a coverage gap, not a deliverable.
2. For each use case, define detection logic grounded in available fields (signature, threshold, anomaly, or correlation) and write it in pseudocode or the platform's query language. Cite the detection reference or ATT&CK technique it implements; mark novel logic as unverified until tested.
3. Predict false positives and the benign activity that triggers them (admin tools, scanners, service accounts, batch jobs), and pair each rule with allowlists, thresholds, and a triage/response note so the SOC can action it.
4. Assemble the set (name -> intent -> ATT&CK ref -> data sources -> logic -> FP profile -> tuning -> severity) and report it as DRAFT content for validation in a test/non-prod ruleset. State assumptions about log completeness and volume.

# Notes

Output is wrong if logic references fields the onboarded sources don't emit (the rule never fires), or if it ships with no FP handling (alert fatigue, the rule gets muted). High-volume or auto-response rules must be validated and approved before production — stage them, don't enable. Cite ATT&CK/detection sources; mark untested logic unverified. Not for log-source onboarding or pipeline engineering, and not for incident investigation — this builds detections, it does not run them.
