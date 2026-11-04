---
name: segregation-of-duties-review
triggers:
  - sod review
  - segregation of duties
  - conflicting access
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Reviews user-to-access assignments against a segregation-of-duties ruleset to find toxic-combination conflicts, producing an SoD conflict matrix with risk-ranked findings. Handles the goal class "given who can do what in a system, identify users who hold incompatible duties and rank the exposure." Produces a per-user, per-conflict listing suitable for owner review and remediation.

# Steps

1. Load the SoD ruleset (conflicting function pairs and their risk rating — e.g. create vendor + approve payment = high) from policy via knowledge_search. If no approved ruleset exists, surface that gap and stop; do not invent conflict pairs.
2. Query the access data with sql_query: join users to roles/entitlements to the underlying business functions. Confirm the join resolves entitlements to the same function vocabulary the ruleset uses — a mismatch silently misses conflicts; reconcile or flag it.
3. Cross every user's effective function set against the ruleset; emit one row per (user, conflict pair) where both functions are held. Carry the rule's risk rating and note any documented mitigating control (e.g. compensating review) from knowledge_search so true exposure isn't overstated.
4. Build the conflict matrix sorted by risk rating then user, and report counts by severity, the population/system scope, and the as-of date. State assumptions (ruleset version, whether role-based or effective/derived access was tested). Hand off to access owners; flag remediation (revocation) as a human decision — do not propose or stage access changes.

# Notes

Output is wrong if access is tested at the role label instead of effective entitlements (nested/inherited grants hide conflicts), if firefighter/emergency and service accounts aren't scoped or excluded with rationale, or if mitigating controls are ignored (false positives) or assumed (false negatives). Point-in-time only — it does not detect a user who exercised both duties over time. Revoking access is irreversible to in-flight work; this skill recommends, the owner decides. Do not use as a privileged-access review or a full IAM certification.
