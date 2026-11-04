---
name: access-review-campaign
triggers:
  - run an access review
  - start a certification campaign
  - do an entitlement review
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Runs a periodic access certification campaign: pulls who-has-what from the identity store, assigns each entitlement to the right reviewer, and produces a certify/revoke decision package. Output is a reviewer-ready worklist plus a staged revoke list — no access is changed automatically.

# Steps

1. Query current grants with `sql_query` (user, entitlement/role, system, grant date, last-used, manager). Pull the campaign scope and policy (review cadence, SoD rules, reviewer mapping) from `knowledge_search`. State the as-of timestamp of the data.
2. Map each entitlement to a reviewer (resource owner or line manager from the query). Flag orphans (no owner), dormant grants (no use within the policy window), and any entitlement violating a separation-of-duties rule found in knowledge.
3. Build per-reviewer worklists: each row carries user, entitlement, justification, last-used, and a recommended action (certify / revoke / investigate) with the rule that drove it. Default high-risk or dormant grants to a revoke recommendation, not certify.
4. Compile the proposed revoke list separately and report both. End by handing the worklists to reviewers and the revoke list to the access owner for execution, stating assumptions about reviewer mapping and any users that could not be matched to an owner.

# Notes

Output is wrong if entitlements are certified by default, if dormant/orphan grants are silently passed, or if the data as-of date is omitted (stale extracts certify access that already changed). Revocation is the irreversible step and is staged for a human — this skill only recommends. Do not use for emergency just-in-time access decisions or for privileged/admin accounts (use privileged-access-review). Cite the query and policy source for every recommendation.
