---
name: access-recertification
triggers:
  - run an access review
  - quarterly recertification
  - entitlement review for this app
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Runs a periodic access review for a system or role population: pulls current entitlements, compares them against policy and peer baselines, flags anomalies (orphaned accounts, SoD conflicts, dormant access, privilege creep), and produces a recertification package with a proposed revoke list. Output is a reviewer-ready package, not an executed revocation.

# Steps

1. Define scope: which application/role/population is under review and the certification period. Use `knowledge_search` to retrieve the governing policy (least-privilege standard, SoD matrix, joiner-mover-leaver rules) and the prior cycle's results; cite them so deviations are traceable.
2. Pull the live entitlement snapshot with `sql_query`: user identity, role/group, grant date, last-login/last-use, grantor, and account status. Record the query and timestamp — the package must show exactly what was reviewed.
3. Run the analysis passes: orphaned accounts (no active owner), dormant access (no use within the policy window), privilege creep (entitlements beyond the role baseline), SoD conflicts (against the matrix), and terminated/transferred users still holding access. Tag each finding with the rule it violates and the evidence row; never assert a violation without the underlying record.
4. Assemble the recertification package — per-reviewer worklists, anomaly summary, and a proposed revoke list ranked by risk — and hand off for sign-off. State assumptions (data freshness, any populations excluded). Mark every revocation as a draft pending reviewer approval; do not execute changes.

# Notes

The output is wrong if the snapshot is stale, if last-use data is missing and you treat absence as "active" (dormancy is then unprovable — flag it as undetermined, not safe), or if you flag an SoD conflict without citing the matrix rule. Revocation is irreversible and can break production access: always stage it for an accountable reviewer; never auto-revoke. Not for incident-driven emergency deprovisioning (that is a separate fast path) or for designing the role model itself.
