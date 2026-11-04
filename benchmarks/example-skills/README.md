# Example skills

A curated set of `SKILL.md` files demonstrating common Lightwork
patterns. Install any of them with:

```bash
maverick skill install ./benchmarks/example-skills/web-research.md
```

Or point at the GitHub raw URL:

```bash
maverick skill install gh:Daybreak-AI-Labs/LightworkOS:benchmarks/example-skills/web-research.md
```

## Catalog

| File | What it does | Tools needed |
|---|---|---|
| [`web-research.md`](web-research.md) | Parallel-fanout research + synthesis | shell, write_file, spawn_swarm |
| [`code-refactor.md`](code-refactor.md) | Test-gated refactoring loop | read_file, write_file, shell, spawn_subagent |
| [`trip-planning.md`](trip-planning.md) | Personalized travel itinerary | write_file, ask_user, spawn_swarm |
| [`codebase-audit.md`](codebase-audit.md) | Multi-axis code audit -> prioritized punch list | shell, read_file, list_dir, spawn_swarm |
| [`ml-paper-summary.md`](ml-paper-summary.md) | 3-level paper summary with honest-limitations section | read_file, write_file, spawn_subagent |

## Contributing your own

1. Write a `SKILL.md` following the schema below.
2. Test it: `maverick skill install ./your-skill.md` then
   `maverick start "<phrase that should trigger it>"`.
3. Open a pull request that adds it to this directory.

## Schema

```markdown
---
name: short-kebab-case-id
triggers:
  - natural language phrase that should activate this skill
  - another phrase
tools_needed:
  - shell
  - write_file
---

# What this skill does

One paragraph.

# Steps

1. ...
2. ...

# Notes

Gotchas, anti-patterns, things that did NOT work.
```

Keep skills mechanical -- a future agent should be able to follow them
without improvising. The `# Notes` section is the most valuable; it's
where we encode what NOT to do.
