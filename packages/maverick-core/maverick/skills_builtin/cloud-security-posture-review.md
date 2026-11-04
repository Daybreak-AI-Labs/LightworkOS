---
name: cloud-security-posture-review
triggers:
  - cloud security
  - cspm
  - misconfiguration
tools_needed:
  - knowledge_search
---
# What this skill does

Reviews a cloud environment's configuration posture (IAM, network, storage, logging, encryption) against established baselines and produces a posture review listing misconfigurations with severity and concrete fixes. Output is a prioritized findings list mapped to benchmark controls (e.g. CIS, provider Well-Architected) and remediation steps.

# Steps

1. Establish the environment and baseline: use `knowledge_search` to pull the org's cloud account/subscription inventory, config exports or CSPM findings, and the applicable benchmark (CIS for the provider, internal standard, or compliance requirement). Assess only against a stated baseline — name it, don't assume one.
2. Review by control domain using the gathered config: IAM (over-privilege, root/admin use, MFA, key age), network (open security groups, public ingress), storage (public buckets, unencrypted volumes), logging/audit (trail enabled, retention), and encryption at rest/in transit.
3. For each misconfiguration record: the control it violates, the affected resource(s), severity (impact x exposure), and whether it is confirmed from config data or inferred. Mark inferred items as unverified pending a config check.
4. Deliver the review: findings ranked by severity, each with the exact remediation (setting/policy change) and the benchmark control reference, plus systemic root causes (e.g. missing guardrail/SCP). End by reporting and stating which domains/accounts were and were not covered.

# Notes

A finding is wrong if it cites no resource and no control reference — every item maps to a real resource from the config and a named benchmark control; mark anything inferred as unverified. Recommend fixes only — do NOT apply IAM, network, or encryption changes yourself; misapplied guardrails can cause outages or lockout, so stage changes for a human to apply with rollback. State coverage honestly: unscanned accounts/regions/services are blind spots, not "clean." Not a substitute for runtime threat detection — this is configuration posture only.
