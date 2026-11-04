# Recipe: Docstring pass

Point the agent at one file and have it add or fix docstrings on the
public functions — no behavior changes. Sub-minute on a small file.

## Goal text

```
Open <path/to/file.py>. For each public (non-underscore) function or
method that is missing a docstring, or whose docstring is stale:

  1. Read the signature and the body.
  2. Write a one-line summary plus an Args/Returns block in the style
     already used elsewhere in this file (match it, don't impose a new one).
  3. Only touch docstrings. Do not change any code, signatures, or imports.

Show the diff at the end. Don't commit.
```

## Tools used

`read_file`, `ast_edit` (or `str_replace` if you prefer line edits),
`preview_diff`.

## Expected runtime

~40-60 seconds on a file with a handful of functions. Under $0.75. Cap
with `MAVERICK_BUDGET_DOLLARS=0.75`.

## Tips

- Keep it to ONE file — a whole-package pass blows past the 60s budget.
- Run `preview_diff` yourself afterward to confirm only docstrings moved.
