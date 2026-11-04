---
name: api-design-review
triggers:
  - api design
  - api review
  - rest design
tools_needed:
  - knowledge_search
---
# What this skill does

Reviews a proposed or existing API contract (REST/RPC spec, OpenAPI doc, or endpoint list) against the dimensions that determine long-term quality: versioning, error semantics, pagination, authentication/authorization, and naming consistency. The output is a structured review with per-issue severity and a concrete fix, grounded in the actual contract under review, not abstract best-practice prose.

# Steps

1. Read the actual contract: endpoints, methods, request/response schemas, status codes, and auth scheme. If only prose exists, list the endpoints you inferred and flag gaps rather than guessing intent.
2. Run `knowledge_search` for the org's API style guide and existing sibling APIs; check the contract against established conventions and cite the source guideline for each deviation you flag.
3. Evaluate each dimension on real endpoints: versioning (is breaking change isolated?), errors (consistent shape, correct status codes, machine-readable codes), pagination (cursor vs offset, stable ordering, limits), auth (every mutating route protected, scopes/least-privilege), and naming/resource modeling consistency.
4. Write findings as a table: dimension, endpoint, severity (blocker/major/minor), and the specific fix. Separate true contract defects from style preferences.
5. Hand off the review, stating assumptions made about unspecified behavior and listing which findings block release versus which are follow-ups.

# Notes

The review is wrong if it flags style nits as blockers or misses an unauthenticated mutating endpoint (always the highest severity). Do not invent endpoints or response shapes that aren't in the contract — mark them unverified. Cite the style guide for convention-based findings. This is advisory: it recommends changes but does not modify the API or merge anything — a human owns acceptance. Not for evaluating a running API's performance or uptime; this reviews the contract shape only.
