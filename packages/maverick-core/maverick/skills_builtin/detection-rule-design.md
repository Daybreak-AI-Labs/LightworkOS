---
name: detection-rule-design
triggers:
  - write a detection rule
  - sigma rule for this behavior
  - alert logic for this technique
tools_needed:
  - knowledge_search
---
# What this skill does

Turns a described adversary behavior (a TTP, an IOC pattern, an abuse case) into a deployable detection rule: matching logic, the data sources it depends on, expected false positives, and tuning notes. Produces a backend-agnostic rule (Sigma form by default) plus a deployment checklist — not a live-pushed alert.

# Steps

1. Pull the behavior into concrete terms: name the technique (map to ATT&CK ID if known), the observable artifacts (process, command line, registry, network, auth event), and the precondition that makes it malicious. Use `knowledge_search` over internal detection libraries and ATT&CK references; cite each source and mark any inferred field as unverified.
2. Identify the required data source and confirm it is actually collected (e.g. Sysmon EID 1, EDR process events, proxy logs, cloud audit trail). If the field you need is not in the available telemetry, say so — the rule is non-functional without it and you must flag the logging gap rather than assume coverage.
3. Write the detection logic: selection criteria, condition, and explicit exclusions for known-benign actors. Keep it specific enough to fire on the behavior and broad enough to survive trivial evasion (avoid matching one literal string an attacker controls). State which evasions it does and does not cover.
4. Add tuning notes (expected FP sources, suppression/baseline guidance, severity, recommended test command) and hand off the rule as a draft. State assumptions about telemetry and environment; recommend a staged rollout (audit/log-only mode first, then alerting) and leave enablement to a human.

# Notes

The rule is wrong if it depends on telemetry you have not confirmed is ingested, if the condition matches a benign default that floods the SOC, or if it keys on an attacker-controlled literal that one flag change evades. Never invent ATT&CK IDs or field names — verify against `knowledge_search` results or mark them unverified. Do not auto-deploy: detection rules are staged log-only and a human enables alerting after FP review. Not for tuning an existing noisy rule (that is alert triage) or for one-off IOC blocks (use a blocklist, not a behavioral rule).
