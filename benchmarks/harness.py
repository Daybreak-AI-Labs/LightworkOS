"""Reproducible benchmark harness.

Runs a benchmark .md file as a Lightwork goal, captures wall-clock /
cost / token / tool-call metrics from the world model, and writes a row
into RESULTS.md.

Usage:

    python benchmarks/harness.py longhorizon/research-report.md \\
        --max-dollars 2.0 \\
        --tag v0.2.0

The harness is intentionally light: it shells out to `maverick start` so
it exercises the same code path as a real user; it then reads the world
model to pull metrics for the just-finished goal.

Comparative numbers vs. other agents (OpenClaw, Hermes) require those
systems to be installed; harness writes Lightwork's row unconditionally
and leaves placeholders for hand-filled comparator rows.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def run_one(
    benchmark_path: Path,
    max_dollars: float,
    max_wall_seconds: float,
    tag: str,
    db_path: Path | None = None,
) -> dict:
    """Run a single benchmark. Returns a metrics dict."""
    spec = benchmark_path.read_text(encoding="utf-8")

    # We don't actually invoke the LLM in CI; export a flag so the
    # harness can be smoke-tested. Real runs require ANTHROPIC_API_KEY.
    dry_run = os.environ.get("MAVERICK_BENCH_DRY_RUN") == "1"

    start = time.monotonic()
    if dry_run:
        # Synthesize a fake successful run -- useful for CI smoke tests.
        wall_seconds = 0.1
        outcome = "dry-run"
        cost = 0.0
        in_tokens = 0
        out_tokens = 0
        tool_calls = 0
    else:
        env = os.environ.copy()
        # `maverick start` runs synchronously (it blocks until the goal
        # finishes); there is no --no-wait option, and passing one aborts the
        # run with a Click usage error before any work happens.
        cmd = [
            "maverick", "start", "--max-dollars", str(max_dollars),
            spec,
        ]
        if db_path is not None:
            env["MAVERICK_DB"] = str(db_path)
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True,
            timeout=max_wall_seconds,
        )
        wall_seconds = time.monotonic() - start
        outcome = "ok" if proc.returncode == 0 else f"exit-{proc.returncode}"

        # Read the most recent episode from the world model.
        from maverick.world_model import WorldModel
        wm = WorldModel(db_path)
        eps = wm.list_episodes(limit=1)
        if eps:
            cost = eps[0].cost_dollars
            in_tokens = eps[0].input_tokens
            out_tokens = eps[0].output_tokens
            tool_calls = eps[0].tool_calls
            outcome = eps[0].outcome or outcome
        else:
            cost = in_tokens = out_tokens = tool_calls = 0

    return {
        "benchmark": str(benchmark_path),
        "tag": tag,
        "agent": "maverick",
        # Provenance: this harness can only measure Lightwork (it shells out
        # to `maverick start`). Comparator rows for other agents are hand-
        # added, so they MUST be marked source=manual to stay honest -- a
        # reader can't otherwise tell a measured row from a typed-in one.
        "source": "measured",
        "wall_seconds": round(wall_seconds, 2),
        "cost_dollars": round(cost, 4),
        "input_tokens": in_tokens,
        "output_tokens": out_tokens,
        "tool_calls": tool_calls,
        "outcome": outcome,
    }


def _markdown_row(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |\n"


def _markdown_cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _ensure_results_table(results_path: Path, cols: list[str]) -> None:
    if not results_path.exists():
        header = _markdown_row(cols)
        divider = "|" + "|".join(["---"] * len(cols)) + "|\n"
        results_path.write_text(
            "# Lightwork benchmark results\n\n"
            "Auto-appended by `benchmarks/harness.py`. Each row is one run.\n\n"
            + header + divider,
            encoding="utf-8",
        )
        return

    lines = results_path.read_text(encoding="utf-8").splitlines(keepends=True)
    header_idx = None
    for i, line in enumerate(lines):
        if line.lstrip().startswith("|") and "benchmark" in line:
            header_idx = i
            break
    if header_idx is None:
        raise ValueError(f"existing results file has no markdown table header: {results_path}")

    header = _markdown_cells(lines[header_idx])
    if header == cols:
        return

    old_cols = [c for c in cols if c != "source"]
    if header != old_cols:
        raise ValueError(
            "existing results markdown header does not match the current schema: "
            f"expected {cols!r} or {old_cols!r}, got {header!r}"
        )

    source_idx = cols.index("source")
    lines[header_idx] = _markdown_row(cols)
    divider_idx = header_idx + 1
    if divider_idx < len(lines) and lines[divider_idx].lstrip().startswith("|"):
        lines[divider_idx] = "|" + "|".join(["---"] * len(cols)) + "|\n"

    for i in range(divider_idx + 1, len(lines)):
        if not lines[i].lstrip().startswith("|"):
            break
        cells = _markdown_cells(lines[i])
        if len(cells) == len(old_cols):
            cells.insert(source_idx, "")
            lines[i] = _markdown_row(cells)
        elif len(cells) != len(cols):
            raise ValueError(
                "existing results markdown row has an ambiguous number of "
                f"cells ({len(cells)}): {lines[i].rstrip()}"
            )

    results_path.write_text("".join(lines), encoding="utf-8")


def append_results(row: dict, results_path: Path) -> None:
    """Append a row to RESULTS.md as a markdown table line.

    Creates the file with header if missing. We use markdown rather than
    JSON because RESULTS.md is the human-readable artifact.
    """
    cols = [
        "benchmark", "tag", "agent", "source", "wall_seconds", "cost_dollars",
        "input_tokens", "output_tokens", "tool_calls", "outcome",
    ]
    _ensure_results_table(results_path, cols)
    line = _markdown_row([str(row.get(c, "")) for c in cols])
    with results_path.open("a", encoding="utf-8") as f:
        f.write(line)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("benchmark", type=Path)
    ap.add_argument("--max-dollars", type=float, default=2.0)
    ap.add_argument("--max-wall-seconds", type=float, default=1800)
    ap.add_argument("--tag", default="local")
    ap.add_argument(
        "--results", type=Path,
        default=Path(__file__).parent / "RESULTS.md",
    )
    ap.add_argument("--db", type=Path, default=None)
    args = ap.parse_args()

    if not args.benchmark.exists():
        print(f"no such benchmark: {args.benchmark}", file=sys.stderr)
        return 2

    row = run_one(
        args.benchmark, args.max_dollars, args.max_wall_seconds,
        args.tag, db_path=args.db,
    )
    append_results(row, args.results)
    print(json.dumps(row, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
