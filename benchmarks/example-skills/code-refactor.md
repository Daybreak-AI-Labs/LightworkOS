---
name: code-refactor
triggers:
  - refactor this code
  - extract a class
  - clean up duplication
  - reorganize the module
tools_needed:
  - read_file
  - write_file
  - shell
  - spawn_subagent
---

# What this skill does

Refactor existing code without changing its behavior. Always works
behind a test gate: tests pass before the change, tests pass after.

# Steps

1. Read the target file(s) with `read_file`.
2. Find or write a test file that exercises the public surface. If
   none exists, write one BEFORE refactoring. The test must pass
   first.
3. Plan the refactor: new module structure, extracted names, what moves
   where. Write it down with `write_file` to `REFACTOR_PLAN.md` so
   future agents can follow.
4. Apply changes one logical step at a time. Run the test suite
   after each step (`shell` -> `pytest -q`).
5. If tests fail, revert the last change before continuing.
6. End with FINAL: a summary of what moved + the test output showing
   green.

# Notes

- NEVER refactor without tests. If the codebase has none, write them
  first.
- Spawn a `revisor` sub-agent if your first pass fails the post-change
  test run; it gets a different prompt + extended thinking.
- Resist the urge to also "improve" adjacent code -- one refactor at
  a time.
