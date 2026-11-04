# Recipe: Dependency migration

Major-version bumps of common libraries (FastAPI 0.x→1.0, Pydantic
v1→v2, Django 4→5, React 17→18). You want the agent to read the
changelog, identify breaking changes, plan the migration, and apply
the non-controversial ones.

## Goal text

```
We're on <library>==<old_version> and want to migrate to <new_version>.

  1. Read the library's CHANGELOG.md or upgrade guide at
     <https://docs.example.com/.../upgrade>.
  2. List every breaking change from <old_version> to <new_version>.
  3. For each, scan the repo for affected call sites
     (use dep_graph and repo_map liberally).
  4. Apply changes for the SAFE breaking changes (renames,
     parameter reorderings, removed-now-default flags) automatically.
  5. For RISKY breaking changes (semantic shifts, async-to-sync,
     security model differences), STOP and ask the user.
  6. Bump the pin in pyproject.toml / requirements.txt last.
  7. Run the test suite. If anything fails, fix or revert.
```

## Tools used

`http_fetch` (changelog), `repo_map`, `dep_graph`, `ast_edit`,
`shell` (run tests), `ask_user` (for the risky-change stop).

## Expected runtime

5-10 minutes on a mid-size repo. Worth budgeting $2-3.

## Tips

- This recipe really benefits from `MAVERICK_FETCH_RESPECT_ROBOTS=1`
  (the agent is hitting third-party docs).
- Use the `recall_past_goals` tool first — you may have done a similar
  migration before, and the agent can re-use the plan.
