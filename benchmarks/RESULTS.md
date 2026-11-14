# Lightwork benchmark results

> **No live-model results are recorded yet.** The only row in the results
> table is a `dry-run` CI smoke (`MAVERICK_BENCH_DRY_RUN=1`). It makes no model
> call and measures nothing. To record a live run, set `ANTHROPIC_API_KEY` and
> run this from the repository root, replacing `v0.1.6` with the release tag
> being measured:
>
> ```bash
> python benchmarks/harness.py benchmarks/longhorizon/research-report.md --max-dollars 2.0 --tag v0.1.6
> ```
>
> The harness appends a `measured` row to this file. Hand-added comparator
> rows must be marked `manual`.

This file is **append-only**, written by `benchmarks/harness.py` and
hand-edited only for comparator rows from external agents.

## Setup

Each row is one run of one benchmark. Columns:

- `benchmark`: path under `benchmarks/`
- `tag`: release tag the run was at (e.g. `v0.1.0`)
- `agent`: `maverick`, `openclaw`, `hermes`, `autogen`, or a single-shot baseline
- `source`: `measured` (auto-written by this harness), `dry-run` (auto-written
  by a run that called no model) or `manual` (hand-added
  comparator row). The harness only measures Lightwork; any other-agent row is
  hand-added and **must** be marked `manual` so measured and typed-in numbers
  are never confused.
- `wall_seconds`: end-to-end clock time
- `cost_dollars`: total API spend (sum across all agents in the swarm)
- `input_tokens`, `output_tokens`: aggregate token usage
- `tool_calls`: how many tool invocations
- `outcome`: `success`, `failure`, `interrupted`, or `dry-run`

## How to reproduce

```bash
# 1. Set credentials
echo 'ANTHROPIC_API_KEY=sk-ant-...' >> ~/.maverick/.env

# 2. Run a benchmark (writes a row below)
python benchmarks/harness.py benchmarks/longhorizon/research-report.md \
    --max-dollars 2.0 --tag v0.1.0

# 3. CI smoke (no API call, just records a dry-run row)
MAVERICK_BENCH_DRY_RUN=1 python benchmarks/harness.py \
    benchmarks/longhorizon/research-report.md --tag ci-smoke
```

## Comparator notes

Lightwork targets **long-horizon work** — multi-day plans, recursive
decomposition, persistent learning. The fair comparison is against
agents that ALSO target multi-step work:

- **OpenClaw** (Rust): subprocess-driven coding agent. Single-shot
  oriented; long-horizon via external scripting.
- **Hermes Agent** (Python): NousResearch's tool-use chat model + harness.
- **AutoGen** (Python): Microsoft's multi-agent framework.
- **Single-shot Sonnet baseline**: one Anthropic call, no tools, no
  decomposition. The "is the agent actually buying us anything" floor.

Comparator rows are filled by hand after running each system's
out-of-the-box configuration on the same benchmark spec. The harness
writes only Lightwork's row.

## Results table

| benchmark | tag | agent | source | wall_seconds | cost_dollars | input_tokens | output_tokens | tool_calls | outcome |
|---|---|---|---|---|---|---|---|---|---|
| benchmarks/longhorizon/research-report.md | local-smoke | maverick | measured | 0.1 | 0.0 | 0 | 0 | 0 | dry-run |
