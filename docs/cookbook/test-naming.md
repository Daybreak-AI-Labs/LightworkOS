# Recipe: Test naming

Rename vague test functions (`test_1`, `test_it_works`) into descriptive
names that say what they assert — no logic changes. Sub-minute per file.

## Goal text

```
Open <path/to/test_file.py>. Find every test function whose name does not
describe what it asserts (e.g. test_1, test_works, test_case_a):

  1. Read each such test's body and its assertions.
  2. Propose a new name of the form test_<subject>_<expected_behavior>
     (snake_case), consistent with the well-named tests already in the file.
  3. Apply the renames. Do NOT change any assertions, fixtures, or
     parametrize args — names only.

Show the diff. Don't commit.
```

## Tools used

`read_file`, `ast_edit`, `preview_diff`.

## Expected runtime

~40-60 seconds on one test module. Under $0.75.

## Tips

- Names-only keeps this safe and fast; a rename never breaks behavior.
- If a test is referenced by name elsewhere (e.g. `-k` filters in CI),
  add *"also grep the repo for the old name and update references."*
