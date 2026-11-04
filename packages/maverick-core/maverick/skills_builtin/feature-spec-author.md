---
name: feature-spec-author
triggers:
  - write a feature spec
  - functional spec for this feature
  - define this feature in detail
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a complete, build-ready specification for a single feature. It converts a one-line ask into precise behavior: the user-facing flow, system rules, edge cases, error states, and testable acceptance criteria — the document an engineer can implement from and a QA can verify against.

# Steps

1. Establish the feature's goal and scope from the user's input and `knowledge_search` over existing product docs, related specs, and prior decisions. Write the problem statement, target user, and an explicit non-goals list. Do not pad scope beyond what was asked.
2. Specify the happy-path behavior step by step (trigger, system response, end state), then enumerate edge cases and error states: empty/missing data, permission denied, concurrency, limits, and offline/failure conditions. Pull any existing constraints (auth model, rate limits, data rules) from the codebase or docs rather than guessing them.
3. Write acceptance criteria as discrete, testable Given/When/Then statements — one per behavior and per edge case — so each maps to a verification.
4. Assemble the spec (goal, scope/non-goals, behavior, edge cases, acceptance criteria, open questions) and hand off. List every open question and every assumption explicitly so a human resolves them before build.

# Notes

A spec is wrong when it states behavior the team hasn't agreed to as if it were decided — keep genuine unknowns in the open-questions list, never resolve them by fabrication. Cite the source for any external constraint (API limit, compliance rule); if unverified, mark it. This is a draft for human review and sign-off, not an authorization to build. Don't use it for vague epics spanning many features (do `user-story-mapping` first) or for pure UI tweaks that need no behavioral contract.
