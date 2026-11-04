---
name: acceptance-criteria-author
triggers:
  - acceptance criteria
  - gherkin
  - definition of done
tools_needed:
  - knowledge_search
---
# What this skill does

Writes testable acceptance criteria for a user story or feature, expressed in Given/When/Then (Gherkin) form. Produces a set of scenarios that pin the story's done-state precisely enough to drive both implementation and test-case design — not vague bullet wishes.

# Steps

1. Read the story: its actor, the action, the value/intent, and any constraints. Use `knowledge_search` to pull the surrounding requirements, business rules, and the team's existing AC/Gherkin conventions so wording and granularity match. Do not invent rules the story does not state — flag gaps as open questions.
2. Identify the distinct behaviors the story implies: the happy path, each business rule or branch, error/validation conditions, and permission or state preconditions. One scenario per behavior keeps them independently testable.
3. Write each scenario in Given (preconditions/context) / When (the action) / Then (the observable, verifiable outcome). Keep outcomes concrete and assertable — a specific value, state, or message, never "it works." Use Scenario Outlines with examples where the same rule spans multiple inputs.
4. Add a Definition of Done checklist that complements the scenarios (tests, docs, observability, rollout) without duplicating them. Report the criteria, list assumptions and any ambiguities you resolved, and hand off for a human to confirm before the story is committed to.

# Notes

Criteria are wrong if a Then is unobservable or untestable, or if they encode a rule absent from the story — mark assumed rules explicitly and route them back to the product owner. Avoid criteria that describe implementation ("the service calls X") rather than behavior. This skill drafts and recommends; the product owner ratifies scope, and committing a story is their irreversible call, not the agent's. Use test-case-design downstream to expand each accepted scenario into concrete cases.
