# Correctness-scoring eval harness

`harness.py` measures the **cost / latency** of a goal run. `evals.py` adds
the missing half: **correctness** — did the agent get the right answer? It
reports `pass@1` per benchmark over a small pluggable interface, so GAIA /
terminal-bench / τ²-bench are reported the same way despite different task
shapes.

## Run it

The real run executes each task as a goal **in-process** via the live solver in
`agent_solver.py` — the same `run_goal` path a user hits — and returns the
agent's `FINAL ANSWER:`. Cost is capped **per task** with `--max-dollars`.

```bash
# Real run (needs a provider key, e.g. ANTHROPIC_API_KEY):
python benchmarks/run_eval.py gaia --dataset path/to/gaia.jsonl \
    --limit 20 --max-dollars 2 --max-wall-seconds 600

# CI / smoke (no keys, no dataset — shipped offline fixture + stub solver):
MAVERICK_EVAL_DRY_RUN=1 python benchmarks/run_eval.py gaia
```

Scores append to `benchmarks/SCORES.md` (a markdown table, like `RESULTS.md`).

**Rough cost:** ~$0.5–$2 per task (multi-step agent on the Opus orchestrator),
so a 20-task slice ≈ $10–$40 and the full GAIA validation split (~165 tasks)
≈ $80–$300. Bound it with `--max-dollars` (per task) and `--limit` (task count).

## The contract (`evals.py`)

A `Benchmark` supplies tasks and a scorer; a `solver` turns a task into the
agent's answer. The solver is **injected** so the whole harness runs in CI
with a deterministic stub — no LLM, no network.

```python
class Benchmark(Protocol):
    name: str
    def load_tasks(self, dataset=None, *, limit=None) -> list[EvalTask]: ...
    def score(self, task: EvalTask, output: str) -> float: ...  # 0.0..1.0

run_benchmark(bench, solver, dataset=..., limit=...) -> {pass_at_1, mean_score, ...}
```

## Benchmarks

| slice | benchmark | scorer |
|---|---|---|
| general assistant | **GAIA** (`eval_gaia.py`) | official normalized exact-match (number / string / list) |
| tool-agent policy | **τ²-bench** (`eval_tau2.py`) | stateful tool domain + DB; graded on final state **and** required actions. The **live solver** (`tau2_solver.py`) runs an agent↔user-simulator conversation over the domain tools. Run: `python benchmarks/eval_tau2.py --limit N --max-dollars 2`; CI/stub: `MAVERICK_EVAL_DRY_RUN=1 …`. |
| CLI ops | **terminal-bench** (`eval_terminal_bench.py`) | Docker-free virtual-FS: graded on final files **and** required commands. The **live solver** (`terminal_solver.py`) drives a real LLM in a tool-calling loop over the env's shell tools. Run: `python benchmarks/eval_terminal_bench.py --limit N --max-dollars 2`; CI/stub: `MAVERICK_EVAL_DRY_RUN=1 …`. |

### Adding the next slice

1. Add `eval_<name>.py` exporting a `Benchmark` class (`name`, `load_tasks`,
   `score`).
2. Ship a tiny offline fixture in `eval_fixtures/` and a test in
   `test_evals.py` that runs it with a stub solver.
3. Register it in `run_eval.py`'s `_BENCHMARKS`.

**terminal-bench** ships its own stateful harness (`eval_terminal_bench.py`):
a task gives starting files + a request, the **live solver** (`terminal_solver.py`)
drives a real LLM in a tool-calling loop over the virtual-FS shell tools, and
`verify` grades the final filesystem (`expected_files` / `absent_files`) **and**
the command log (`required_commands`). Validated for free with a scripted
FakeLLM (`test_terminal_solver.py`). For tasks that need **real command execution** (run code, run a test
suite, chmod+exec) the virtual FS can't do, `container_terminal_solver.py` runs
the agent against a throwaway **isolated Docker container** (`--network none`,
memory/pid-capped) and grades by running the verify command *inside* it
(exit 0); `eval_fixtures/container_terminal_hard.jsonl` holds such tasks.
Its loop + grading are unit-tested free (in-memory fake container); a live run
needs a Docker daemon.

**τ²-bench** is **dual-control** (agent↔user): the live solver (`tau2_solver.py`)
runs a Lightwork agent in a tool-loop talking to a **user-simulator** LLM that
holds the scenario, until the customer's goal is resolved; `verify` grades the
final DB state **and** the required tool actions. Validated for free with
scripted FakeLLMs for *both* sides (`test_tau2_solver.py`).
