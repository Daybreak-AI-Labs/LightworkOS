# Recipe: Extract a god-function

Break one sprawling function into named, testable units — behavior unchanged.

## Goal text

```
Refactor <FILE::function> (it's too long/does too much):
  1. Identify the distinct responsibilities inside it; name each.
  2. Extract them into small helpers with clear inputs/outputs. No behavior
     change — pure restructuring. Keep the public signature stable.
  3. Run the existing tests after each extraction; they must stay green. If
     there are none, add one characterization test FIRST that pins current
     output, then refactor under it.
Output the diff + confirmation the tests pass.
```

## Tools used

`read_file`, `repo_map`, `apply_patch`, `shell` (tests).

## Expected runtime

~3 min. Budget-cap $1-2.
