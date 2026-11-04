---
name: ediscovery-scoping
triggers:
  - scope an ediscovery collection
  - legal discovery scope
  - define collection scope for a matter
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a defensible e-discovery collection scope for a legal matter: the set of custodians to preserve, the data sources to collect from, the date range, and the search keywords/terms. Output is a structured scope document an attorney can approve before any collection runs.

# Steps

1. Read the matter intake from knowledge_search (complaint/legal hold notice, claims, parties, key dates). If no matter record exists, stop and request it — never guess the scope.
2. Identify custodians: search knowledge_search for named parties, their reports, and roles touching the claims. List each with role and why they are relevant; mark any inferred (vs. named) custodian as unverified.
3. Enumerate data sources per custodian (email, chat, file shares, ticketing, devices) and set the date range from the claim window plus a documented buffer. Cite the source for each boundary date.
4. Draft keyword/term lists tied to the claims, noting expected over/under-inclusiveness. Hand off the scope (custodians, sources, date range, terms) marked DRAFT FOR COUNSEL APPROVAL, stating every assumption and unverified inference.

# Notes

Wrong output usually means missing custodians (under-collection = spoliation risk) or an over-broad date range (cost blowout). Keyword lists are starting points, not final — they require attorney review and may need sampling/iteration. This skill drafts and recommends only; preservation holds, collection, and any deletion are irreversible and must be authorized by counsel. Do not use it to actually issue holds or collect data, and do not use it when no legal hold or matter record exists.
