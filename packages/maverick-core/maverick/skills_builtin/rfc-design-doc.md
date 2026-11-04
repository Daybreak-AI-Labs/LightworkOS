---
name: rfc-design-doc
triggers:
  - write an rfc for this change
  - draft a design doc
  - technical proposal for review
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a technical RFC / design document that proposes a significant change for peer review: it frames the context and constraints, lays out the realistic options, recommends one with explicit trade-offs, and surfaces risks and a rollout plan. The output lets reviewers agree or dissent on the decision, not just the prose.

# Steps

1. Establish context: pull the existing architecture, related RFCs/ADRs, constraints, and the requirement driving the change via knowledge_search. State the problem, goals, non-goals, and hard constraints; if a constraint is assumed rather than confirmed, label it.
2. Enumerate at least two viable options (including do-nothing or the status-quo extension); for each, describe the design and its concrete trade-offs (cost, latency, complexity, blast radius, migration). Do not strawman the alternatives.
3. State the Decision: name the recommended option and the deciding criteria, the trade-offs accepted, and what would change the decision. Add cross-cutting impact — data model, API/contract compatibility, security, operability, migration/rollback.
4. Add risks, open questions, a phased rollout/test plan, and reviewers; assemble the RFC, mark assumptions and unverified estimates, and route for review. The decision stays "proposed" until reviewers approve.

# Notes

An RFC is wrong when it presents a single option as inevitable, hides the trade-offs of the chosen path, or omits migration/rollback for a change that needs it. Performance, cost, and capacity numbers must be cited or marked as estimates — never fabricated. The document recommends; the reviewers/owner decide, and irreversible steps (schema migrations, data deletion, contract removals) are staged behind that approval and the project's migration gates. Not for trivial reversible changes that a PR description covers, and not a substitute for a PRD when the question is product, not engineering.
