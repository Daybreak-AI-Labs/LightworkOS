# Recipe: Commit message

You staged a change and want a clean Conventional-Commits message without
typing it yourself. Sub-minute, no code changes.

## Goal text

```
Look at the currently staged diff (git diff --cached). Write a single
Conventional Commits message for it:

  1. Pick the right type prefix: feat / fix / perf / chore / ci / docs /
     refactor / test.
  2. Subject line <= 72 chars, imperative mood, starts with a letter.
  3. If the diff touches more than one concern, add a short body with one
     bullet per concern.

Output ONLY the commit message (no commentary). Don't commit anything.
```

## Tools used

`preview_diff`, `shell` (read-only `git diff --cached`).

## Expected runtime

~30-45 seconds on a small diff. Well under $0.50. Cap with
`MAVERICK_BUDGET_DOLLARS=0.5`.

## Tips

- Keep the budget tight: this is a one-shot reasoning task, no tool loop.
- If you like the message, pipe it straight in:
  `git commit -m "$(maverick start '...')"`.
