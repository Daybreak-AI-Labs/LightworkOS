---
name: swot-and-porters
triggers:
  - swot
  - porters five forces
  - strategic analysis
tools_needed:
  - knowledge_search
  - web_search
---
# What this skill does

Produces a paired strategic assessment of a named company or business unit: a SWOT (Strengths, Weaknesses, Opportunities, Threats) and a Porter's Five Forces analysis (rivalry, new entrants, substitutes, supplier power, buyer power). Output ties the two frameworks together into a short set of strategic implications a strategist can act on. Each factor is grounded in a cited fact, not an unsupported assertion.

# Steps

1. Pin the subject and scope: the exact entity, the market/segment it competes in, and the geography. If the user left any of these open, state the scope you assumed before proceeding.
2. Gather evidence with `knowledge_search` for internal/owned context (positioning, financials, prior analyses) and `web_search` for external signals (competitors, regulation, market shifts). Record a source for every material factor; mark anything you could not source as `[unverified]`.
3. Build the SWOT: place each evidenced factor in exactly one quadrant (internal/controllable -> S/W; external/uncontrollable -> O/T). Drop generic filler; keep only factors specific to this entity and material to strategy.
4. Build Porter's Five Forces: rate each force High/Medium/Low with a one-line justification tied to a cited fact (concentration, switching costs, capital barriers, substitute availability, input criticality).
5. Cross-link and report: derive 3-6 strategic implications where SWOT and the forces reinforce each other (e.g. a Strength that blunts a High rivalry force). Hand off the SWOT grid, the forces table, and the implications, restating scope and listing any `[unverified]` items.

# Notes

The output is wrong when factors are generic boilerplate ("strong brand") rather than entity-specific and sourced, when a factor is miscategorized (a market trend filed as a Strength), or when force ratings carry no justification. This is a draft strategic input, not a decision: recommend, do not commit the business to any move. Do not use for a single-product feature comparison (use a competitive landscape map) or when the entity/market is unspecified — resolve scope first.
