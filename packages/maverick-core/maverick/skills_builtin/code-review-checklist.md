---
name: code-review-checklist
triggers:
  - code review
  - pr review
  - change review
tools_needed:
  - read_file
---
# What this skill does

Reviews a code change (a diff, PR, or set of touched files) against a structured checklist and produces a findings list spanning correctness, design, and risk. Output is a reviewer-quality report: each finding cites the exact file and line, states severity, and proposes a concrete fix or a question — not a rubber-stamp approval.

# Steps

1. Establish scope: read the diff or the named changed files with `read_file`, plus the immediate callers/callees and any test files they touch. Note the change's stated intent so you can judge whether the code matches it.
2. Pass for correctness: trace control flow and data flow for each changed unit. Check edge cases (empty/null, boundaries, concurrency, error paths), input validation, resource cleanup, and that tests actually exercise the new behavior. Flag logic that diverges from the stated intent.
3. Pass for design: assess naming, cohesion, duplication, leaky abstractions, API/interface compatibility, and whether the change fits existing patterns in the surrounding files (read them to confirm, don't assume).
4. Pass for risk: identify security-sensitive surfaces (auth, input handling, secrets, shell/SQL injection, deserialization), migration/rollback safety, performance regressions, and observability gaps. Report findings grouped by category, each with file:line, severity (blocker/major/minor/nit), and a suggested action; end by stating what you could NOT verify (e.g. runtime behavior, external systems).

# Notes

The report is wrong if a finding cites a line not in the read file, or asserts a bug without tracing the path that triggers it — quote the code. Distinguish facts (visible in the diff) from inferences (likely but unverified) and mark the latter. This skill reviews and recommends; it does not merge, push, or approve — a human owns the merge decision. Do not use it as a substitute for running the tests or the build; it reasons over source, it does not execute. When the diff is large, review by cohesive unit rather than top-to-bottom and say so.
