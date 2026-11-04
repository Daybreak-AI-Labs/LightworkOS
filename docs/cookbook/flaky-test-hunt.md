# Recipe: Flaky-test hunt

A test fails intermittently. Find which one, why, and propose a fix —
without "fixing" it by adding a retry.

## Goal text

```
A test in this repo is flaky (passes sometimes, fails others). Find and fix
the root cause:

  1. Run the suite a few times: `pytest -q` (repeat 3x). Collect any test
     that passes on one run and fails on another.
  2. For each flaky test, read it and its subject. Identify the source of
     non-determinism: order dependence, real time/`sleep`, network, a shared
     temp file, an unseeded random, or reliance on dict/set ordering.
  3. Propose the smallest fix that removes the non-determinism (seed the RNG,
     freeze time, isolate the tempdir, make the assertion order-independent).
     Do NOT paper over it with a retry/rerun.
  4. Apply the fix and re-run that test 5x to confirm it's stable.

Report the test, the root cause in one sentence, and the diff.
```

## Tools used

`shell` (run pytest), `read_file` / `repo_map` (find the test + subject),
`apply_patch` (the fix), `preview_diff`.

## Expected runtime

~2-4 minutes depending on suite speed. Budget-cap at $1-2.

## Tips

- If nothing flakes in 3 runs, add `-p no:randomly` vs `-p randomly` to expose
  order dependence specifically.
- Follow up with: *"Add a regression note to the test docstring explaining the
  non-determinism you removed."*
