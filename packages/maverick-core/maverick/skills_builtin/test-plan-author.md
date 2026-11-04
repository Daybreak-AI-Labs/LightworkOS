---
name: test-plan-author
triggers:
  - write a test plan
  - draft a verification plan
  - build a QA plan for this release
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Produces a verification plan for a release or feature: enumerated test cases, a coverage matrix mapping cases to requirements, and explicit entry/exit criteria. The output is a reviewable artifact a QA owner uses to gate a release, not a vague checklist.

# Steps

1. Gather the source of truth — requirements, acceptance criteria, the change scope (PR/spec/ticket). Use `read_file` on the spec and `knowledge_search` for prior test plans and known-flaky areas. List each requirement you found; mark any you could not locate as UNVERIFIED rather than inventing scope.
2. Derive test cases per requirement: for each, write id, preconditions, steps, expected result, and type (functional, regression, negative, edge, performance, security). Include negative and boundary cases, not just the happy path.
3. Build the coverage matrix: requirement -> case ids, and flag any requirement with zero cases as a gap. Note environments, data fixtures, and dependencies each case needs.
4. Define entry criteria (build available, env ready, fixtures loaded) and exit criteria (pass thresholds, max open severities, sign-off owner). Report the plan and hand off, stating assumptions about untestable paths (e.g. live-LLM or external integrations) and listing coverage gaps for a human to accept or close.

# Notes

The plan is wrong if cases are unexecutable (missing preconditions/data), if "expected result" is ambiguous, or if a requirement maps to no case — silent gaps are the main failure mode. Do not assert coverage you cannot trace to a requirement. Exit thresholds are a recommendation; the release decision belongs to the QA owner. Not for ad-hoc exploratory testing or for re-running an existing suite — this authors the plan, it does not execute tests.
