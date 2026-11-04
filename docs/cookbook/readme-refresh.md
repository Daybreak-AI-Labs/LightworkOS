# Recipe: README refresh

Re-sync a stale README with what the code actually does.

## Goal text

```
The README at <PATH> has drifted. Update it against the code:
  1. Diff the documented install/usage/commands against reality (entry points,
     CLI --help, public API). List every mismatch.
  2. Fix the install command, the quickstart, and the feature list to match the
     current code. Remove sections describing removed features.
  3. Don't invent features — only document what exists. Flag anything you
     couldn't verify instead of guessing.
Output the diff.
```

## Tools used

`read_file`, `repo_map`, `shell` (`--help`, entry points), `apply_patch`.

## Expected runtime

~2 min. Budget-cap $1.
