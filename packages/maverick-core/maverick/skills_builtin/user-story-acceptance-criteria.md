---
name: user-story-acceptance-criteria
triggers:
  - turn this need into a user story
  - write acceptance criteria for this feature
  - break this into backlog items
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Converts a stated need or feature request into buildable, testable backlog items. Produces user stories in "As a / I want / so that" form, each with Given/When/Then acceptance criteria a developer can build to and a tester can verify, plus an INVEST check that flags stories too big or too vague to pull into a sprint.

# Steps

1. Ground in the actual requirement: read the request, related tickets, and product context via `knowledge_search` and `read_file`. Identify the user role, the goal, and the underlying value; mark any assumed behavior as "[assumption — confirm with PO]".
2. Write each story as "As a <role>, I want <capability>, so that <value>", scoped to a single coherent outcome — split anything that bundles multiple goals.
3. For each story, write acceptance criteria in Given/When/Then, covering the happy path plus the obvious edge and error cases; keep them observable and binary (pass/fail), not implementation detail.
4. Run an INVEST check (Independent, Negotiable, Valuable, Estimable, Small, Testable) and flag failures — e.g. "too large, split into A/B" or "not testable, criteria are subjective."
5. Hand off the stories with their open questions and assumptions listed; state that scope and priority are recommendations the product owner confirms.

# Notes

Stories are wrong when acceptance criteria are subjective ("works well"), describe the UI instead of the behavior, or smuggle in solution decisions the team should own. Do not invent requirements to fill gaps — list them as questions for the product owner. This skill drafts and recommends a split/priority; the PO owns final scope and ordering. Don't use it for pure spikes/research or for bugs (those want a defect report with repro steps, not a story).
