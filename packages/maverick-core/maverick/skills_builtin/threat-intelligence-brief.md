---
name: threat-intelligence-brief
triggers:
  - threat intel
  - threat brief
  - ioc analysis
tools_needed:
  - web_search
  - knowledge_search
---
# What this skill does

Produces an actionable threat-intelligence brief on a named threat (actor, campaign, malware family, or CVE under active exploitation), filtered to what is relevant to the organization's actual stack and exposure. Output covers the threat, its TTPs and IOCs, relevance, and prioritized recommended actions — each claim cited.

# Steps

1. Pin the scope: the specific threat in question and the org's environment it must be assessed against (stack, internet-facing assets, sector). Pull the latter from knowledge_search; if unavailable, state the assumed environment.
2. Gather current intel via web_search from primary/reputable sources (vendor advisories, CISA/national CERTs, the affected vendor) — capture publication dates and map TTPs to MITRE ATT&CK technique IDs. Prefer the original advisory over secondary reporting.
3. Extract IOCs (hashes, domains, IPs, CVEs) and assess relevance: does this threat target software, sectors, or exposures the org actually has? Distinguish "applies to us" from "noteworthy but out of scope" with the reason for each.
4. Write the brief — summary, TTPs/IOCs, relevance verdict, and ranked recommended actions (detect, patch, hunt) — every factual line cited with source and date. Report, flagging stale (>30 day) or single-source claims and noting that response actions are for a human to authorize.

# Notes

The brief is wrong if IOCs or attribution are stated without a dated source, or if relevance is asserted without grounding in the org's real assets — mark unverified attribution as such, since threat actor naming is often contested across vendors. Intel decays fast: note the as-of date and treat anything beyond ~30 days as needing refresh. This skill informs and recommends only; it does not block IPs, push detections, or patch — those are staged for a human to authorize. Do not use it as a substitute for an incident-response runbook during an active breach.
