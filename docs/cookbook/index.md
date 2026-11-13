# Lightwork cookbook

End-to-end recipes you can paste into `maverick start "..."` (or into a
GitHub issue body when using the `agent-on-pr` reusable workflow).

Each recipe is:

- **Self-contained**: doesn't assume you have anything beyond a fresh
  Lightwork install (native installer or [source install](../source-install.md))
  + `maverick init`.
- **Bounded**: each recipe gives its own runtime and budget estimate; set
  an explicit cap appropriate to that recipe (the examples range up to $3).
- **Real**: copy-paste-and-run, no placeholder TODOs in the goal text.

| Recipe | When to use |
|--------|-------------|
| [PR review](./pr-review.md)            | After pushing a branch; surface logic bugs before asking a human |
| [Dependency migration](./dep-migrate.md) | Bump a library across a major version with breaking changes |
| [Repo onboarding](./repo-onboarding.md) | First-day-on-the-job tour of a codebase you didn't write |
| [Issue triage](./issue-triage.md)      | Inbox of GitHub issues you want to label and group |
| [Research deep-dive](./research.md)    | Pick a paper / library / topic and produce a 1-page brief |
| [Flaky-test hunt](./flaky-test-hunt.md) | A test fails intermittently; find + fix the root cause (no retries) |
| [Dependency CVE triage](./cve-triage.md) | A scanner flagged a CVE; decide if it's reachable here + the safe bump |
| [CSV cleanup](./csv-cleanup.md)        | Normalize + flag a messy CSV without fabricating values |
| [Bug report → failing test](./bug-repro.md) | Turn a bug report into a minimal failing regression test (TDD step 1) |
| [Slow SQL optimize](./sql-optimize.md) | Read a query plan and propose the index/rewrite that fixes a slow query |
| [Dockerfile harden](./dockerfile-harden.md) | Fix size/cache/security smells in a Dockerfile |
| [API client from OpenAPI](./api-client-gen.md) | Generate a thin typed client + smoke test from a spec |
| [README refresh](./readme-refresh.md) | Re-sync a drifted README with what the code actually does |
| [License audit](./license-audit.md) | Check dependency licenses against how you ship |
| [Type-annotation pass](./type-annotate.md) | Add type hints to an untyped module and prove them |
| [Profile a slow function](./perf-profile.md) | Find the real bottleneck and fix the one that matters |
| [Coverage gap](./coverage-gap.md) | Find the riskiest untested branch and write the test |
| [Extract a god-function](./refactor-extract.md) | Split a sprawling function into named units, behavior unchanged |
| [Config format migration](./config-migrate.md) | Migrate a config file format losslessly with a round-trip check |
| [Infer a JSON schema](./json-schema-infer.md) | Infer + validate a JSON Schema from sample data |
| [HTML accessibility audit](./accessibility-audit.md) | Find + fix the high-impact a11y issues in a page/template |

## Quick hits (under 60 seconds)

Single-shot recipes that finish in well under a minute, budget-capped
below $1. Great for muscle-memory tasks you'd otherwise do by hand.

| Recipe | When to use |
|--------|-------------|
| [Commit message](./commit-message.md)   | Write a Conventional-Commits message for the staged diff |
| [Explain an error](./explain-error.md)  | Paste a stack trace; get the root cause + most likely fix |
| [Regex builder](./regex-builder.md)     | Describe a pattern in English; get a tested regex back |
| [Changelog entry](./changelog-entry.md) | Turn a commit range into one user-facing CHANGELOG line |
| [Release notes](./release-notes.md)     | Draft user-facing release notes from PRs/commits since the last tag |
| [Docstring pass](./docstring-pass.md)   | Add/fix docstrings on one file's public functions |
| [Test naming](./test-naming.md)         | Rename vague tests to describe what they assert |
| [Env-var audit](./env-audit.md)         | Diff env vars read by code against what's documented |
| [Log triage](./log-triage.md)           | Bucket a noisy log; surface the error spike + likely cause |

## Submitting your own

PRs welcome. Criteria:

1. Self-contained: works against any reasonable repo, no
   user-specific setup.
2. Budget-bounded: < $1 on Sonnet 4.6 budget caps.
3. Documented expected output (what success looks like, what failure
   modes are common).
4. Tested at least once by the contributor against a real repo.
