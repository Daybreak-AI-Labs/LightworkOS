# Recipe: Env-var audit

Find every environment variable the code reads and check it against the
`.env.example` / docs. Surfaces undocumented or unused knobs. Sub-minute.

## Goal text

```
Audit this repo's environment-variable usage:

  1. Find every place the code reads an env var (os.environ, os.getenv,
     process.env). Use repo_map + grep-style reads.
  2. Build the set of var names actually read.
  3. Compare against .env.example (or README) if one exists.
  4. Report two lists:
       - read by code but NOT documented
       - documented but NOT read by code (possibly dead)

Output as two short markdown lists. Don't change anything.
```

## Tools used

`repo_map`, `read_file`, `shell` (read-only grep through the tree).

## Expected runtime

~45-60 seconds on a small/mid repo. Under $0.75. Cap with
`MAVERICK_BUDGET_DOLLARS=0.75`.

## Tips

- On a large monorepo this can exceed 60s — scope it to one package by
  adding *"only under packages/<name>/"* to the goal.
- Follow up with: *"Add the undocumented vars to .env.example with a
  one-line comment each."*
