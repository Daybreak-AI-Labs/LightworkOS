---
name: residency-egress-validate
triggers:
  - check data residency posture
  - validate egress lock
  - sovereign cloud gaps
  - data residency audit
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Maps declared data-residency commitments against the actual egress-lock configuration and the real locations where SaaS sub-processors store data, flags cross-border leakage, and surfaces sovereign-cloud gaps. The goal class is "verify that data actually stays where it is promised to stay": reconcile the stated residency posture with the as-configured reality, region by region and service by service.

# Steps

1. Read the residency commitments with read_file (contracts, data-processing agreements, policy statements) to establish, per data class, the regions/jurisdictions where data is required to remain.
2. Inventory the actual data locations: cloud-region configuration, egress-lock / region-pinning settings, backup and replication targets, and where each SaaS sub-processor stores and processes the data; search knowledge_search for a provider's documented regional behavior when it is unclear.
3. Reconcile declared vs actual and flag every gap: an egress-lock that is not actually enforced, a backup or DR region outside the committed jurisdiction, telemetry/logs shipped cross-border, or a sub-processor operating in a non-permitted location.
4. Identify sovereign-cloud gaps specifically (where a sovereignty requirement demands an in-jurisdiction operator or key control that the current setup does not meet) and produce a prioritized remediation list ranked by data sensitivity and leakage severity.

# Notes

The leaks are usually in the places nobody pins: backups, disaster-recovery replicas, logs, and telemetry routinely egress to a default region even when the primary store is correctly pinned — so checking only the primary data store gives false comfort. A residency CLAIM in a contract is not a CONTROL; verify the egress-lock is actually enforced, not merely configured. Sub-processors inherit the obligation but often sit elsewhere; trace the full chain. Sovereignty is stricter than residency (it can require an in-country operator and key custody), so do not conflate the two. This skill validates posture and reports gaps for the security/compliance team; it does not change cloud configuration or move data.
