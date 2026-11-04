# Recipe: Test coverage gap

Find the riskiest untested branch in a module and write the test for it.

## Goal text

```
For <PATH/TO/module.py>, close the most important coverage gap:
  1. Run coverage on its test(s): `pytest --cov=<module> --cov-report=term-missing`.
  2. Of the uncovered lines, pick the highest-risk branch (error handling, an
     edge case, a security/validation path) — not a trivial getter.
  3. Write a focused test that exercises it and asserts the right behavior; run
     it green. Don't chase 100% — one meaningful test.
Output the test + the new covered lines.
```

## Tools used

`shell` (pytest --cov), `read_file`, `apply_patch`.

## Expected runtime

~2 min. Budget-cap $1.
