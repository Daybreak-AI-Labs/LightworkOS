# Recipe: Bug report → failing test

Turn a vague bug report into a minimal, failing regression test — the TDD
first step — before anyone attempts a fix.

## Goal text

```
Here is a bug report: <PASTE THE REPORT: what they did, what happened, what
they expected>. Reproduce it as a failing test:

  1. Locate the code path the report describes (repo_map + grep the symbols
     and error text it mentions).
  2. Write the SMALLEST test that reproduces the reported behavior and asserts
     the EXPECTED (correct) outcome — so it fails today for the right reason.
  3. Run it; confirm it fails, and that the failure matches the report (not an
     unrelated error like a typo or missing import).
  4. Do NOT fix the bug. Leave the failing test + a one-paragraph root-cause
     hypothesis for the human/next run.

Output the test file path, the failing assertion, and the hypothesis.
```

## Tools used

`repo_map` / `shell grep` (find the path), `apply_patch` (write the test),
`shell` (run it), `read_file`.

## Expected runtime

~1-3 minutes. Budget-cap at $1.

## Tips

- This is the front half of TDD; follow up with: *"Now make the failing test
  pass with the smallest change, and keep every other test green."*
- If the report lacks detail, the run will tell you exactly what it couldn't
  reproduce — that's a useful "needs-info" signal to send back to the reporter.
