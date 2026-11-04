---
name: attack-surface-review
triggers:
  - attack surface
  - external exposure
  - asset discovery
tools_needed:
  - web_search
  - knowledge_search
---
# What this skill does

Enumerates an organization's external (internet-facing) attack surface and assesses the risk of exposed assets. Produces a review listing discovered assets (domains, subdomains, IPs, exposed services/ports, third-party footprint) each scored by exposure risk, with recommended actions.

# Steps

1. Establish scope from authoritative input: use `knowledge_search` for the org's known domains, IP ranges, asset inventory, and ownership records. Only assets the org owns or is authorized to assess are in scope — confirm scope before enumerating; never probe out-of-scope targets.
2. Discover surface using `web_search` over passive/OSINT sources (public DNS, cert transparency, exposed-service registries, code/doc leaks). Record provenance for each asset and mark anything unconfirmed as candidate, not owned.
3. Assess each asset: service/version exposed, whether it should be public, auth posture, and known-exposure signals (deprecated TLS, default pages, leaked endpoints). Rank by risk = exposure x sensitivity x likely exploitability.
4. Deliver the review: inventory table of exposed assets with risk scores, top risks (shadow IT, unintended public services, stale subdomains for takeover), and recommended remediations. End by reporting and stating scope/coverage assumptions and known blind spots.

# Notes

Use passive/OSINT discovery only — do NOT run active scans, exploitation, or intrusive probing; those are authorized, staged actions a human owns. Output is wrong if an asset's ownership is asserted without evidence (risk of flagging someone else's infra) — cite the discovery source and mark unverified ownership. Coverage is never complete; state that passive discovery misses assets and is a point-in-time snapshot. Not for internal-network/lateral-movement assessment — this is external-facing surface only.
