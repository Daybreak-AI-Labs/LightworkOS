# Recipe: Repo onboarding

You inherited a codebase you didn't write. Get the agent to produce
the tour you wish someone had written.

## Goal text

```
Produce a one-page onboarding brief for this repository. Cover:

  1. What does it do? (one-paragraph high-level summary)
  2. Top-level architecture: list the 5 most important modules /
     packages and what each is responsible for. Use repo_map + dep_graph.
  3. The "happy path": pick one representative use case and walk
     through the call chain from entry point to result.
  4. Build / test / lint commands (from CONTRIBUTING.md or
     pyproject.toml scripts).
  5. Conventions to keep: any obvious patterns (error handling,
     logging, config, dependency injection) you can spot from
     reading 3-4 representative files.
  6. Open questions: list 3-5 things you'd ask a maintainer if you
     could.

Output as a single markdown document, ~500 words. Don't change anything.
```

## Tools used

`repo_map`, `dep_graph`, `read_file`, `web_search` (for unfamiliar
deps).

## Expected runtime

~3 minutes. $0.50-1.00 on Sonnet 4.6.

## Tips

- Pipe to a file: `maverick start "..." > onboarding.md`.
- After the brief, ask: *"Now answer my 'open questions' yourself
  by reading more code."* — a follow-up goal often closes most of them.
