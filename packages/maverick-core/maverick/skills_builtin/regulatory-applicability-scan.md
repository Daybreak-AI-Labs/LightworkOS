---
name: regulatory-applicability-scan
triggers:
  - regulatory applicability
  - which regulations apply
  - reg scan
tools_needed:
  - knowledge_search
  - web_search
---
# What this skill does

Given a described business activity, product, or jurisdiction, determines WHICH regulations and statutory obligations plausibly apply, and produces an applicability matrix mapping each activity element to the obligations it triggers. Used to scope a compliance assessment before deeper analysis; it identifies candidate regimes, not a legal opinion.

# Steps

1. Pin the scope from real inputs: the activity, the entity type, the data/asset classes handled, customer segments, and every operating jurisdiction. Do not infer jurisdictions or data types that the user did not state — list them as "unspecified" instead.
2. For each jurisdiction x activity element, knowledge_search the internal regulatory library for governing regimes; fall back to web_search for primary sources (regulator sites, official gazettes, statute text). Capture the citation (regulator, rule number, effective date) for each hit.
3. Build the applicability matrix: rows = activity elements; columns = regime, triggering condition, specific obligation, applies (yes/likely/no/unknown), and source citation. Mark any obligation lacking a primary-source citation as "unverified".
4. Report the matrix, list the jurisdictions/data types treated as unspecified, and hand off the "likely" and "unknown" rows for human legal review. State that this is a scoping aid, not a legal determination.

# Notes

Output is wrong if it asserts applicability without a cited triggering condition, or silently drops a stated jurisdiction. Never fabricate rule numbers or effective dates — mark unverified and stop. Regulatory thresholds (revenue, headcount, data-subject counts) change; treat any threshold older than the source's effective date as stale. Do NOT use this to render a final compliance sign-off or to clear an activity as exempt — exemptions and final calls are a human attorney's decision.
