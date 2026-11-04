---
name: test-strategy-design
triggers:
  - test strategy
  - testing approach
  - test pyramid
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a test strategy for a system or feature: which test levels to invest in, what each level covers, target coverage, and the tooling/CI gates that enforce it. Produces a strategy document mapping risks to test levels, not a generic "write more tests" memo.

# Steps

1. Characterize the system under test: its architecture (units, services, integrations, UI), the highest-risk areas (data integrity, money, auth, concurrency), and the deployment/release model. Use `knowledge_search` to pull existing conventions, prior test layouts, and CI gates so the strategy matches house practice rather than reinventing it.
2. Define the test pyramid for this system: assign responsibilities to each level (unit, integration/contract, end-to-end, plus non-functional — performance, security, accessibility where relevant). State what each level owns and what it explicitly does NOT, to avoid overlap and slow E2E bloat.
3. Set coverage and quality targets per level (e.g. unit line/branch goals, critical-path E2E scenarios, contract tests for each external boundary), and tie them to the riskiest areas identified in step 1 — high risk earns deeper coverage.
4. Specify tooling and gates: test runners, fixtures/data strategy, mocking boundaries, environment needs, and which checks block merge vs. run nightly. Report the strategy as a level-by-level table plus a short rationale; state assumptions about the stack and flag any level you could not ground in retrieved conventions.

# Notes

The strategy is wrong if it prescribes coverage numbers without tying them to risk, or recommends tools the codebase does not use — always confirm conventions via `knowledge_search` and mark anything unverified. Avoid a top-heavy pyramid (many slow E2E, few units): it is the most common failure mode and produces flaky, expensive suites. This skill recommends an approach; it does not write the tests or change CI config — a human ratifies gate changes, which are often irreversible policy. Skip it for a trivial single-function change where test-case design alone suffices.
