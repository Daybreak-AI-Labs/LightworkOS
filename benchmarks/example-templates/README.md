# Example goal templates

Reusable goal bodies with parameter substitution. Run any of them with:

```bash
maverick start --template <name> --param key=value --param key2=value2
```

For example:

```bash
maverick start --template compare-options \
  --param category="vector databases" \
  --param option_a="pgvector" \
  --param option_b="Qdrant"

maverick start --template trip-plan \
  --param destination="Lisbon" \
  --param duration="5 days"

maverick start --template standup --param project="Lightwork"
```

## Catalog

| Template | What it does | Required params |
|---|---|---|
| [`compare-options.md`](compare-options.md) | Side-by-side comparison of two alternatives | `category`, `option_a`, `option_b` |
| [`trip-plan.md`](trip-plan.md) | Day-by-day travel itinerary | `destination`, `duration` |
| [`standup.md`](standup.md) | Daily standup from git log + workspace notes | `project` |
| [`code-review.md`](code-review.md) | Review the latest commit for bugs and style | `branch` |
| [`bug-repro.md`](bug-repro.md) | Reproduce a reported bug with a failing test, propose a fix | `report` |
| [`refactor.md`](refactor.md) | Split a function into smaller tested units | `target` |
| [`add-feature.md`](add-feature.md) | Add a CLI flag with help text and a test | `flag`, `command`, `behavior` |
| [`write-tests.md`](write-tests.md) | Cover a low-coverage file to >=80% | `project` |
| [`research-library.md`](research-library.md) | Evaluate a library vs an alternative | `library`, `alternative` |
| [`migrate-dependency.md`](migrate-dependency.md) | Plan + apply a dependency version bump | `library`, `old_version`, `new_version` |

## Schema

```markdown
---
title: <Title with {{ params }}>
budget_dollars: <float, default 5.0>
budget_wall_seconds: <float, default 3600>
params:
  - first_required_param
  - second_required_param
---
The goal body. Use {{ first_required_param }} and {{ second_required_param }}
where you'd otherwise hardcode values.
```

Variables that aren't supplied at runtime are left in the rendered output
(useful for partial templates), but any param listed in `params:` is
**required** -- omitting one raises an error before the agent starts.

## Installing your own templates

Drop a `.md` file in `~/.maverick/templates/` and it's available
immediately. User templates take precedence over bundled ones when
they share a name.
