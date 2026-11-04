---
name: vuln-prioritization-ssvc
triggers:
  - which CVEs do we patch first
  - prioritize these vulnerabilities
  - SSVC decision for this finding
tools_needed:
  - knowledge_search
  - web_search
---
# What this skill does

Takes a set of vulnerability findings and produces a prioritized remediation order driven by exploitability and impact rather than raw CVSS. Applies an SSVC-style decision (exploitation status, exposure, mission/safety impact) enriched with EPSS and known-exploited evidence, and outputs a ranked list with a defensible rationale per item.

# Steps

1. Gather the findings: CVE/identifier, affected asset, asset exposure (internet-facing vs internal), and business/mission criticality. If exposure or criticality is missing, flag it — SSVC cannot rank an asset whose exposure is unknown, so mark those items "needs asset context" rather than guessing.
2. Enrich each CVE with exploitation evidence: check CISA KEV and active-exploitation reporting via `web_search`, retrieve the EPSS score, and pull internal context (compensating controls, prior incidents) via `knowledge_search`. Cite each source with its date; threat data is time-sensitive and a stale "no known exploit" is misleading.
3. Apply the SSVC decision per finding: map exploitation (none/PoC/active), exposure, automatability, and impact to an outcome (Track / Track* / Attend / Act). Record which input drove each decision so the ranking is auditable, not a black-box score.
4. Produce the prioritized list ordered by SSVC outcome then EPSS, with a one-line rationale and recommended SLA per item, and hand off. State assumptions (asset data freshness, controls credited) and present it as a recommendation for the remediation owner to schedule — do not initiate patching.

# Notes

The ranking is wrong if it leans on CVSS base score alone (it ignores real exploitability), if KEV/EPSS data is stale, or if an asset's exposure was assumed rather than verified. Never fabricate an EPSS value or exploitation status — cite or mark unverified. This produces a recommendation only; patch deployment is change-managed and irreversible in effect, so a human owner schedules it. Not for triaging a single actively-exploited zero-day (that is incident response) or for the deep technical write-up of one CVE.
