---
name: prd-author
triggers:
  - write a prd for this feature
  - draft product requirements
  - spec this feature for build
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a build-ready Product Requirements Document for a product or feature: a single document stating the problem, the target users, prioritized requirements, success metrics, and explicit scope. The output is concrete enough that design and engineering can estimate and build from it without re-deriving intent.

# Steps

1. Gather grounding: pull the originating request, customer evidence, prior PRDs, and any analytics or support themes via knowledge_search. Capture the problem and who has it; if user evidence is thin, mark it unverified rather than inventing personas or numbers.
2. Write the spine — Problem (why now, evidence), Users (segments and primary persona with their job-to-be-done), and Goals/Non-goals. State the measurable outcome the feature must move.
3. Specify Requirements as prioritized, testable statements (MoSCoW or P0/P1/P2), each tied to a user need; add Success Metrics (target metric + baseline + guardrail) and explicit out-of-scope items so the boundary is unambiguous.
4. Add open questions, dependencies, and assumptions; assemble the PRD, flag every unverified claim, and hand off to product/eng review. Do not mark it approved — that is the product owner's decision.

# Notes

A PRD is wrong when it specifies a solution instead of a problem, lists requirements with no success metric, or leaves scope open so the build expands silently. Keep requirements outcome-oriented and testable; vague verbs ("improve", "optimize") without a target metric are a defect. Never fabricate user counts, revenue, or research findings — cite the source or mark unverified. Not for tracking implementation tasks (use an RFC/design doc and tickets) or for a fix with no product decision.
