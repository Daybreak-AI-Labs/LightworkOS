---
name: product-requirements-doc
triggers:
  - prd
  - product requirements
  - spec a feature
tools_needed:
  - knowledge_search
---
# What this skill does

Writes a product requirements document (PRD) for a single feature. Produces a structured spec covering the problem, target users, goals/non-goals, functional and non-functional requirements, and success metrics — scoped tightly enough for design and engineering to act on. This drafts a spec; it does not commit roadmap or approve build.

# Steps

1. Gather grounding context with `knowledge_search`: the originating problem or request, supporting evidence (user feedback, data, support themes), the affected user segment, and any related existing features or prior specs. If the problem is stated as a solution ("add a button"), trace it back to the underlying user problem before writing.
2. Write the framing sections: problem statement (who hurts, how often, current cost), target users/personas, and explicit goals and non-goals so scope boundaries are unambiguous. Cite the evidence behind each claim; mark anything assumed as unverified.
3. Specify requirements: functional requirements as testable user-facing behaviors (ideally user stories with acceptance criteria), plus non-functional constraints (performance, security, accessibility, scale). Flag open questions and dependencies rather than guessing.
4. Define success metrics (the primary metric the feature moves plus guardrail metrics) and hand off the PRD for review, stating assumptions, open questions, and what's out of scope. Note that prioritization and the build decision belong to product/eng leadership.

# Notes

Wrong if it specifies a solution without an evidenced problem, if requirements aren't testable (no acceptance criteria = ambiguous build), or if success metrics are vanity numbers not tied to the stated problem. Don't fabricate user evidence or data — cite sources or label claims unverified, and list open questions instead of inventing answers. This is a draft for human review; it does not authorize building, allocate resources, or set commitments. Do NOT use it for a multi-feature initiative or strategy (use a roadmap/strategy doc), or for a pure bug fix where a ticket suffices.
