# Run Lightwork in GitHub Actions

Drive a Lightwork swarm from your own CI with the composite action in
[`deploy/github-action/`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/deploy/github-action/). Hand it a goal (or a
[goal template](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/benchmarks/example-templates/)) and a dollar cap; it
installs from that reviewed Lightwork checkout, runs `maverick start`, and writes the answer to
the job summary.

## Quickstart

```yaml
name: Ask Lightwork
on:
  workflow_dispatch:
    inputs:
      goal:
        description: "What should the swarm do?"
        required: true
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: Daybreak-AI-Labs/LightworkOS/deploy/github-action@<reviewed-full-40-character-commit-sha>
        with:
          goal: ${{ inputs.goal }}
          max-dollars: "0.50"
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

1. Add your provider key as a repo **secret** (`ANTHROPIC_API_KEY`).
2. Replace the placeholder with a reviewed full 40-character commit SHA; do
   not use a mutable branch or tag.
3. Keep `max-dollars` small to start — it's a hard cap the kernel enforces.

## Common patterns

- **Review pull requests** with the `code-review` template.
- **Chain the answer** into a PR comment via the `result` output and
  `actions/github-script`.
- **Use any provider** by setting its env var on the job instead of
  `anthropic-api-key`.

Full input/output reference and copy-paste examples:
[`deploy/github-action/README.md`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/deploy/github-action/README.md).

## What's gated

The full swarm needs a provider key and spends real budget, so it does not
run in this repo's CI. The action's `dry-run: true` mode (install +
command resolution, no LLM calls) is what's smoke-tested in
[`.github/workflows/github-action.yml`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/.github/workflows/github-action.yml).

## See also

- [`benchmarks/example-templates/`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/benchmarks/example-templates/) — the
  ready-made goal templates the action can run.
- [Drive Lightwork from another language](./clients/typescript-quickstart.md)
  — the MCP client surface, for *calling* a local Lightwork from your app
  (vs. *running* one in CI here).
